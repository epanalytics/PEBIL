
/*
 * PAPI Loop Instrumentation
 * The instrumentation reads the env var PEBIL_HWC0, PEBIL_HWC1, ... up to PEBIL_HWC31, 
 * in the order,
 * but stops at the first that is not defined (no gaps allowed).
 * The env variables should be set to PAPI present events, e.g. PAPI_TOT_CYC.
 * Then, for each loop instrumented, the value of the counters specified is accumulated
 * and reported on at the end of execution. The valses are printed in a meta_%.lpiinst file.
 * There is no check that events are compatible, please use the papi_event_chooser to verify
 * events compatibility.
 *
 * Usage example:
 * pebil --tool LoopIntercept --app bench --inp outer.loops --lnc libpapiinst.so,libpapi.so 
 * export PEBIL_HWC0=PAPI_TOT_INS
 * export PEBIL_HWC1=PAPI_TOT_CYC
 * export PEBIL_HWC_SET_NUMBER=0  (0 if you want to call the set 0, but can use any int)
 * ./bench.lpiinst
 * grep Thread bench.set_0.meta_0.lpiinst | awk '{print $3/$4}' # compute IPC of loops
 *
 * By default, counter collection for nested loops are enabled. If there are overhead-related
 * issues (e.g., inner loops that are entered too many times), then you can use 
 * "PEBIL_DISABLE_NESTING" to disable nesting measurements. If the specified set of loops 
 * have the nesting relationsip, the instrumented binary will error out with the 
 * relevant message.
 * 
 * The CPU clock frequency can either be hard-coded (see the CLOCK_RATE_HZ above) or
 * it can be passed on as an env variable -- i.e., by defining the PEBIL_TIMER_CPU_FREQ
 * env variable and setting it to the CPU frequency of the system in Hz. 
 * For CPU frequency scaling experiments, one need to set this variable to the nominal/base 
 * CPU frequency only; i.e., no need to set this to individual scaled CPU frequencies.
 */

#include <InstrumentationCommon.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <sys/un.h>
#include <papi.h>
#include <iostream>
#include <fstream>
#include <sstream>

#include <PAPIInst.hpp>

// mandel's CPU Frequency: you can either hard-code the frequency here
// or use the PEBIL_TIMER_CPU_FREQ env var.
static uint32_t timerCPUFreq=3200000000;
#define CLOCK_RATE_HZ 3200000000

static uint32_t hwcSetNumber=0;
static uint32_t disableNesting=0;

// Xeon Phi Max Rate
//#define CLOCK_RATE_HZ 1333332000

inline uint64_t read_timestamp_counter(){
  unsigned low, high;
  __asm__ volatile ("rdtsc" : "=a" (low), "=d"(high));
  return ((unsigned long long)low | (((unsigned long long)high) << 32));
}

DataManager<PAPIInst*>* AllData = NULL;

PAPIInst* GeneratePAPIInst(PAPIInst* counters, uint32_t typ, image_key_t iid,
			   thread_key_t tid, image_key_t firstimage) {

  PAPIInst* retval;
  retval = new PAPIInst();
  retval->master = counters->master && typ == AllData->ImageType;
  retval->application = counters->application;
  retval->extension = counters->extension;
  retval->loopCount = counters->loopCount;
  retval->loopHashes = counters->loopHashes;
  retval->tmpValues= new values_t[retval->loopCount];
  retval->accumValues = new values_t[retval->loopCount];
  retval->num = 0;
  retval->papiMeasurementsStarted=0;
  retval->currentlyMeasuring=0;
  retval->eventSet=PAPI_NULL;

  /* loop timer additions */
  retval->loopTimerAccum = new uint64_t[retval->loopCount];
  retval->loopTimerLast = new uint64_t[retval->loopCount];
  memset(retval->loopTimerAccum, 0, sizeof(uint64_t) * retval->loopCount);
  memset(retval->loopTimerLast, 0, sizeof(uint64_t) * retval->loopCount);
  /* loop timer additions done */

  /* The CPU clock frequency can either be hard-coded (see the CLOCK_RATE_HZ above) or
   * it can be passed on as an env variable -- i.e., by defining the PEBIL_TIMER_CPU_FREQ
   * env variable and setting it to the CPU frequency of the system in Hz. 
   * For CPU frequency scaling experiments, one need to set this variable to the nominal/base 
   * CPU frequency only; i.e., no need to set this to individual scaled CPU frequencies.
   */
  if (ReadEnvUint32("PEBIL_TIMER_CPU_FREQ", &timerCPUFreq)) {
    inform << "Received custom PEBIL_TIMER_CPU_FREQ ***(in MHz)** from the user :: " <<
      timerCPUFreq << endl;
    // convert timerCPUFreq from MHz to Hz
    timerCPUFreq=timerCPUFreq*1000;
  } else {
    timerCPUFreq=CLOCK_RATE_HZ;
  }

  /* Hardware counter measurements are usually done in multiple iterations; with each iteration
   * measuring a set of compatible counters. To give a name/id to different sets, use this env
   * variable. By default, if the var is not set, the set id is set to 0.
   */
  if (ReadEnvUint32("PEBIL_HWC_SET_NUMBER", &hwcSetNumber)) {
    inform << "Received hardware counter set number from user :: " << hwcSetNumber << endl;
  }

  /* By default, this tool allows for nested loop measurements. If for some reason the nesting
   * exposes overhead issues (e.g., the inner loops might have a very high visit count), you can
   * set PEBIL_DISABLE_NESTING to 1 or higher and disable nested measurements. 
   * If nested measurements are disabled, and the user tries to provide loops that 
   * are nested, then the instrumented binary will error out.   
   */

  if (ReadEnvUint32("PEBIL_DISABLE_NESTING", &disableNesting)) {
    inform << "Received a disable nesting directive from the user:: " << disableNesting << endl; 
  }

  return retval;
}

void DeletePAPIInst(PAPIInst* counters){
  /* loop timer additions */
  delete counters->loopTimerAccum;
  delete counters->loopTimerLast;
  /* loop timer additions done */

}

uint64_t ReferencePAPIInst(PAPIInst* counters){
  return (uint64_t)counters;
}

extern "C"
{
  int32_t loop_entry(uint32_t loopIndex, image_key_t* key) {
    thread_key_t tid = pthread_self();

    PAPIInst* counters = AllData->GetData(*key, pthread_self());
    assert(counters != NULL);

    int eventSet=counters->eventSet;
    
    // see if there are any active loops
    if(counters->currentlyMeasuring!=0) {
      // read the counters and associate the counter values to all the active loops
      //PAPI_stop_counters(counters->tmpValues[loopIndex], counters->num);
      // using the low-level PAPI call to control overhead
      PAPI_read(eventSet, counters->tmpValues[loopIndex]);
      // if the nested measurements are allowed
      if(!disableNesting) {
	for (std::set<int>::iterator it=counters->activeLoops.begin();
	     it!=counters->activeLoops.end(); ++it)

	  for(int i=0;i<counters->num;i++)
	    counters->accumValues[*it][i]+=counters->tmpValues[loopIndex][i];
      } else {
	cerr << "Error: PEBIL_DISABLE_NESTING is set to " << disableNesting << ". " <<
	  "But the set of loops provided for measurements are nested.\n" <<
	  "Please provide non-nested set of loops for measurements." << ENDL;
	exit(-1);
      }
    }
  
    // increment the currentlyMeasuring count
    counters->currentlyMeasuring++;
    // insert this loop to the actively measuring set
    counters->activeLoops.insert(loopIndex);
    
    /* loop timer additions */
    assert(counters->loopTimerLast != NULL);
    counters->loopTimerLast[loopIndex] = read_timestamp_counter();
    /* loop timer additions done */

    // AT: Initialize PAPI for each thread.
    if(!counters->num) {
      /* Initialization */
      int retval=PAPI_library_init(PAPI_VER_CURRENT);
      if (retval != PAPI_VER_CURRENT) {
	fprintf(stderr, "PAPI library init error!\n");
	exit(1);
      }
      
      /* Create the Event Set */      
      if (PAPI_create_eventset(&eventSet) != PAPI_OK) {
	fprintf(stderr, "PAPI create event set error!\n");
	exit(1);
      }
      
      int eventCode=counters->eventCode;
      
      while(counters->num < MAX_HWC) {
	char hwc_var[32];
	sprintf(hwc_var, "PEBIL_HWC%d", counters->num);
	char* hwc_name = getenv(hwc_var);
	if(hwc_name) {
	  int retval = PAPI_event_name_to_code(hwc_name, counters->events+counters->num);
          if(retval != PAPI_OK) {
	    fprintf(stderr, "Unable to determine code for hwc %d: %s, %d\n",
		    counters->num, hwc_name, retval);
          } else {
	    fprintf(stderr, "Thread 0x%llx parsed counter %s\n", tid, hwc_name);
          }
	  if (PAPI_add_event(eventSet, *(counters->events+counters->num)) != PAPI_OK) {
	    fprintf(stderr, "PAPI add event error! Either the specified counter(s) not available or compatible.\n");
	    exit(1);
	  }
	  ++counters->num;
	} else {
	  if(counters->num == 0) {
	    fprintf(stderr, "No counters defined in the env. Adding PAPI_TOT_CYC as default. \n");
	    PAPI_add_event(eventSet, PAPI_TOT_CYC);
	    *(counters->events+counters->num)=PAPI_TOT_CYC;
	    ++counters->num;
	  } else {
	    break;
	  }
	}
	fprintf(stderr, "Parsed %d counters for thread: 0x%llx\n", counters->num, tid);
      }
    }

    // start the counters
    // if this is the first entry, start the measurements
    if(counters->papiMeasurementsStarted==0) {
      
      /* not doing the checking; not good, but checking for overhead */
      PAPI_start(eventSet);
      /* with the check; uncomment for debugging purposes. */
      /*
	if (PAPI_start(eventSet) != PAPI_OK) {
	fprintf(stderr, "Error in PAPI start!\n");
	exit(1);
	}
      */
      // indicate that the measurements have started 
      counters->papiMeasurementsStarted=1;
    } else {
      // else reset the counters (again doing it without the check)
      PAPI_reset(eventSet);
    }
    counters->eventSet = eventSet;

    return 0;
  }

  int32_t loop_exit(uint32_t loopIndex, image_key_t* key) {
    
    uint64_t now =read_timestamp_counter();
    thread_key_t tid = pthread_self();

    PAPIInst* counters = AllData->GetData(*key, pthread_self());

    int eventSet=counters->eventSet;
    PAPI_read(eventSet, counters->tmpValues[loopIndex]);
    
    /* loop timer additions */
    uint64_t last = counters->loopTimerLast[loopIndex];
    counters->loopTimerAccum[loopIndex] += now - last;
    /* loop timer additions done */
    
    // add the read counters to all active loops
    for (std::set<int>::iterator it=counters->activeLoops.begin();
	 it!=counters->activeLoops.end(); ++it) {
      for(int i=0;i<counters->num;i++) {
	counters->accumValues[*it][i]+=counters->tmpValues[loopIndex][i];
      }
    }
    
    // decrease the currentlyMeasuring counter by 1.
    counters->currentlyMeasuring--;
    // remove this loop from the active loop set.
    counters->activeLoops.erase(loopIndex);
    
    // if there are active loops remaining, we will need to restart the counters
    if(counters->currentlyMeasuring!=0) {
      PAPI_reset(eventSet);
    }

    return 0;
  }

  void* tool_dynamic_init(uint64_t* count, DynamicInst** dyn, bool* isThreadedModeFlag) {
    InitializeDynamicInstrumentation(count, dyn,isThreadedModeFlag);
    //InitializeDynamicInstrumentation(count, dyn);
    return NULL;
  }

  void* tool_mpi_init() {
    return NULL;
  }

  void* tool_thread_init(thread_key_t tid) {
    if (AllData){
      if(isThreadedMode())	
	AllData->AddThread(tid);
    } else {
      ErrorExit("Calling PEBIL thread initialization library for thread " <<
		hex << tid << " but no images have been initialized.",
		MetasimError_NoThread);
    }
    return NULL;
  }

  void* tool_thread_fini(thread_key_t tid) {
    return NULL;
  }

  void* tool_image_init(void* args, image_key_t* key, ThreadData* td) {

    PAPIInst* counters = (PAPIInst*)args;

    set<uint64_t> inits;
    inits.insert(*key);
    SetDynamicPoints(inits, false);

    if (AllData == NULL){
      AllData = new DataManager<PAPIInst*>(GeneratePAPIInst, DeletePAPIInst, ReferencePAPIInst);
    }

    AllData->AddImage(counters, td, *key);

    counters = AllData->GetData(*key, pthread_self());
	
    if(PAPI_num_counters() < PAPI_OK) {
      fprintf(stderr,"PAPI initialization failed");
      return NULL;
    }
    
    return NULL;
  }

  void* tool_image_fini(image_key_t* key)
  {
    image_key_t iid = *key;

    if (AllData == NULL){
      ErrorExit("data manager does not exist. no images were intialized", MetasimError_NoImage);
      return NULL;
    }

    PAPIInst* counters = AllData->GetData(iid, pthread_self());
    if (counters == NULL){
      ErrorExit("Cannot retrieve image data using key " << dec << (*key), MetasimError_NoImage);
      return NULL;
    }

    if (!counters->master){
      fprintf(stderr, "Image is not master, skipping\n");
      return NULL;
    }

    char outFileName[1024];
    // want a different name ending than lpiinst - from counters->extension
    sprintf(outFileName, "%s.set_%0d.meta_%0d.%s", counters->application, hwcSetNumber,
	    GetTaskId(), "lppapiinst");

    FILE* outFile = fopen(outFileName, "w");
    if (!outFile){
      cerr << "error: cannot open output file %s" << outFileName << ENDL;
      exit(-1);
    }

    //print title of PAPI event names
    char EventName[512];
    int i,j,retval;
    char** units;
    // AT: changed the counters->num to MAX_HWC
    units=new char*[MAX_HWC];
    //units=new char*[counters->num];
    PAPI_event_info_t evinfo;
	
    for(i=0;i<counters->num;i++)
      {
	units[i]=new char[PAPI_MIN_STR_LEN];
	PAPI_event_code_to_name(*(counters->events+i),EventName);
	retval = PAPI_get_event_info(*(counters->events+i),&evinfo);
	if (retval != PAPI_OK) {
	  cerr<<"\n\t Error getting event info\n";
	  exit(-1);
	}
	strncpy(units[i],evinfo.units,PAPI_MIN_STR_LEN);
	fprintf(outFile,"%s ",EventName);
      }
    fprintf(outFile,"\n");

    //print image hex: loop hex:
    //then next line is Thread: threadhex Time: time hwc values
    // to match lpiinst style (hwc values is addition for papi version)
    for (set<image_key_t>::iterator iit = AllData->allimages.begin(); iit != AllData->allimages.end(); ++iit) {
      PAPIInst* imageData = AllData->GetData(*iit, pthread_self());
      uint64_t imgHash = *iit; 	
      uint64_t* loopHashes = imageData->loopHashes;
      uint64_t loopCount = imageData->loopCount;
		
      for (uint64_t loopIndex = 0; loopIndex < loopCount; ++loopIndex) {
	uint64_t loopHash = loopHashes[loopIndex];
	fprintf(outFile, "0x%llx:0x%llx:\n", imgHash, loopHash);
	for (set<thread_key_t>::iterator tit = AllData->allthreads.begin();
	     tit != AllData->allthreads.end(); ++tit) {
	  PAPIInst* icounters = AllData->GetData(*iit, *tit);
	  fprintf(outFile, "\tThread: 0x%llx Time: %f ",
		  *tit,
		  (double)(icounters->loopTimerAccum[loopIndex]) / timerCPUFreq);
		
	  int hwc;
	  double scaledValue;
	  for(hwc = 0; hwc < icounters->num; ++hwc) {
	    PAPI_event_code_to_name(*(icounters->events+hwc),EventName);
	    retval = PAPI_get_event_info(*(icounters->events+hwc),&evinfo);
	    if (retval != PAPI_OK) {
	      cerr<<"\n\t Error getting event info\n";
	      exit(-1);
	    }
				      
	    if(strstr(units[hwc],"nJ")) {
	      scaledValue=(double)( icounters->accumValues[loopIndex][hwc] /(1.0e9) );
	      double watts=scaledValue/((double)(icounters->loopTimerAccum[loopIndex]) / CLOCK_RATE_HZ);
	      fprintf(outFile,"\t%.4f \n",watts);
	    }
	    else {
	      fprintf(outFile,"\t%lld",icounters->accumValues[loopIndex][hwc]);
	    } 
	  }
	  fprintf(outFile, "\n");
	}
      } 
    }

    fflush(outFile);
    fclose(outFile);
    return NULL;
  }
};

// helpers borrowed from Simulation.cpp

bool ParsePositiveInt32(string token, uint32_t* value){
  return ParseInt32(token, value, 1);
}
                
// returns true on success... allows things to continue on failure if desired
bool ParseInt32(string token, uint32_t* value, uint32_t min){
  int32_t val;
  uint32_t mult = 1;
  bool ErrorFree = true;
  
  istringstream stream(token);
  if (stream >> val){
    if (!stream.eof()){
      char c;
      stream.get(c);

      c = ToLowerCase(c);
      if (c == 'k'){
	mult = KILO;
      } else if (c == 'm'){
	mult = MEGA;
      } else if (c == 'g'){
	mult = GIGA;
      } else {
	ErrorFree = false;
      }

      if (!stream.eof()){
	stream.get(c);

	c = ToLowerCase(c);
	if (c != 'b'){
	  ErrorFree = false;
	}
      }
    }
  }

  if (val < min){
    ErrorFree = false;
  }

  (*value) = (val * mult);
  return ErrorFree;
}

// returns true on success... allows things to continue on failure if desired
bool ParsePositiveInt32Hex(string token, uint32_t* value){
  int32_t val;
  bool ErrorFree = true;
   
  istringstream stream(token);

  char c1, c2;
  stream.get(c1);
  if (!stream.eof()){
    stream.get(c2);
  }

  if (c1 != '0' || c2 != 'x'){
    stream.putback(c1);
    stream.putback(c2);        
  }

  stringstream ss;
  ss << hex << token;
  if (ss >> val){
  }

  if (val <= 0){
    ErrorFree = false;
  }

  (*value) = val;
  return ErrorFree;
}


char ToLowerCase(char c){
  if (c < 'a'){
    c += ('a' - 'A');
  }
  return c;
}

bool ReadEnvUint32(string name, uint32_t* var){
  char* e = getenv(name.c_str());
  if (e == NULL){
    return false;
    inform << "unable to find " << name << " in environment" << ENDL;
  }
  string s (e);
  if (!ParseInt32(s, var, 0)){
    return false;
    inform << "unable to parse " << name << " in environment" << ENDL;
  }
  return true;
}

