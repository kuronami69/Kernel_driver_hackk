#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// Utility functions
uint64_t get_tick_count64()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000 + ts.tv_nsec / (1000 * 1000));
}

pid_t get_name_pid(const char *name)
{
    FILE *fp;
    pid_t pid = -1;
    char cmd[0x100];

    snprintf(cmd, sizeof(cmd), "pidof %s", name);
    fp = popen(cmd, "r");
    if (fp)
    {
        fscanf(fp, "%d", &pid);
        pclose(fp);
    }
    else
    {
        perror("[-] Failed to execute pidof");
    }
    return pid;
}

int main(int argc, char const *argv[])
{
    c_driver driver;

    const char *process_name = "com.tencent.tmgp.sgame";
    const char *module_name = "libunity.so";
    pid_t pid = get_name_pid(process_name);
    if (pid <= 0)
    {
        fprintf(stderr, "[-] Failed to get PID for %s\n", process_name);
        return 1;
    }

    printf("pid = %d\n", pid);

    if (!driver.initialize(pid))
    {
        fprintf(stderr, "[-] Driver initialization failed\n");
        return 1;
    }

    // 调用 OP_INIT_KEY 进行密钥初始化
    char key[] = "my_secret_key";  // 你可以传递你需要的密钥
    if (!driver->init_key(key))
    {
        printf("[-] Failed to initialize key\n");
        return -1;
    }

    uintptr_t base = driver.get_module_base(module_name);
    if (base == 0)
    {
        fprintf(stderr, "[-] Failed to get base address for module %s\n", module_name);
        return 1;
    }

    printf("base = %lx\n", base);

    const size_t read_count = 1;
    uint64_t now = get_tick_count64();
    uint64_t result = 0;

    for (size_t i = 0; i < read_count; ++i)
    {
        result = driver.read<uint64_t>(base);
    }

    printf("Read %ld times took %lfs\n", read_count,
           (double)(get_tick_count64() - now) / 1000.0);
    printf("result = %lx\n", result);

    return 0;
}
