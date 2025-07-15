#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <time.h>
#include <link.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/shm.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#define MAX_RETRY_TIME 60
#define RECV_BUFFER_SIZE 0x100000
#define min(a, b) ((a) < (b) ? (a) : (b))


size_t input_buffer_size = 0x100000;
char* payload_buffer = NULL;
void* trace_buffer = NULL;
int trace_buffer_size = 0;
unsigned char* execution_path = NULL;
struct timeval timeout;
unsigned char* __quic_response = NULL;

void capabilites_configuration(bool timeout_detection, bool agent_tracing);
void start_target();




void capabilites_configuration(bool timeout_detection, bool agent_tracing) {
    static bool done = false;

    if(!done){
        /* Create trace_buffer with shared memory */
        int shmid = shmget(0x1337, 0x10000, IPC_CREAT | 0666);

        printf("[capablities] trace_buffer shmid: %d\n", shmid);
        char buffer[20] = {0};
        sprintf(buffer, "%d", shmid);
        setenv("__AFL_SHM_ID", buffer, 1);
        sprintf(buffer, "%d", 0x10000);
        setenv("__AFL_SHM_ID_SIZE", buffer, 1);
        trace_buffer = shmat(shmid, NULL, 0);
        printf("[capablities] trace_buffer: %p\n", trace_buffer);
        memset(trace_buffer, 0xff, 0x10000);

        
        /* Create quic_response with shared memory */
        shmid = shmget(0x1339, 0x100000, IPC_CREAT | 0666);

        printf("[capablities] quic_response shmid: %d\n", shmid);
        sprintf(buffer, "%d", shmid);
        setenv("__QUIC_RESPONSE", buffer, 1);
        printf("env __QUIC_RESPONSE: %s\n", buffer);
        sprintf(buffer, "%d", 0x100000);
        setenv("__QUIC_RESPONSE_SIZE", buffer, 1);
        printf("env __QUIC_RESPONSE_SIZE: %s\n", buffer);
        __quic_response = shmat(shmid, NULL, 0);
        printf("[capablities] __QUIC_RESPONSE: %p\n", __quic_response);
        memset(__quic_response, 0x0, 0x100000);
        
        /* Create execution_path with shared memory */
        shmid = shmget(0x1338, 0x100000, IPC_CREAT | 0666);

        printf("[capablities] execution_path shmid: %d\n", shmid);
        sprintf(buffer, "%d", shmid);
        setenv("__EXECUTION_PATH", buffer, 1);
        printf("env __EXECUTION_PATH: %s\n", buffer);
        sprintf(buffer, "%d", 0x100000);
        setenv("__EXECUTION_PATH_SIZE", buffer, 1);
        printf("env __EXECUTION_PATH_SIZE: %s\n", buffer);
        execution_path = shmat(shmid, NULL, 0);
        printf("[capablities] execution_path: %p\n", execution_path);
        memset(execution_path, 0x0, 0x100000);
        done = true;
    }
}

void start_target() {

    /* Run start script */
    int ret = system("RUST_BACKTRACE=1 nohup target/debug/quic_converter_nyx 2>&1 |tee /tmp/target/log.txt &");
    sleep(1);
    FILE* file = fopen("/tmp/target/log.txt", "r");

    char buffer[RECV_BUFFER_SIZE];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0'; // Null-terminate the string
        printf("[harness] Target log: %s\n", buffer);
    } 
    fclose(file);


}

int main() {
    printf("[harness] Harness started!\n");
    capabilites_configuration(false, true);

    payload_buffer = mmap(NULL, input_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(payload_buffer, 0, input_buffer_size);
    unsigned char memory[59] =
    {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x2b, 0x02, 0x27, 0x83, 0x31, 0x05, 0x01, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
        0xe1, 0x5e, 0x00, 
    };
    memcpy(payload_buffer, memory, sizeof(memory));


    printf("[harness] Starting target...\n");
    start_target();
    memcpy(execution_path+1, payload_buffer+1, input_buffer_size - 1);
    execution_path[0] = payload_buffer[0];
    while (1) {
        if (execution_path[0] != 0) {
            printf("[harness] Execution path is not empty, processing payload...\n");
            // sleep(0.05);
            sleep(1);
        }
        else {
            break;
        }
    }
    printf("execution_path: ");
    for(int i=0;i<0x100;i++){
        printf("%02x", execution_path[i]);
    }
    printf("\n");
    printf("quic_response: ");
    for(int i=0;i<0x100;i++){
        printf("%02x", __quic_response[i]);
    }
}
