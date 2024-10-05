#include <sys/fcntl.h>
#include <sys/ioctl.h>

#define DEVICE_NAME "/dev/HY"

class c_driver
{
private:
    int fd;
    pid_t pid;

    typedef struct _COPY_MEMORY
    {
        pid_t pid;
        uintptr_t addr;
        void *buffer;
        size_t size;
    } COPY_MEMORY, *PCOPY_MEMORY;

    typedef struct _MODULE_BASE
    {
        pid_t pid;
        char name[0x100]; // Buffer is directly part of struct to avoid dynamic allocation
        uintptr_t base;
    } MODULE_BASE, *PMODULE_BASE;

    enum OPERATIONS
    {
        OP_INIT_KEY = 0x800,
        OP_READ_MEM = 0x801,
        OP_WRITE_MEM = 0x802,
        OP_MODULE_BASE = 0x803,
    };

    bool is_driver_open() const {
        return fd > 0;
    }

public:
    c_driver()
        : fd(-1), pid(0)
    {
        fd = open(DEVICE_NAME, O_RDWR);
        if (fd == -1)
        {
            perror("[-] Failed to open driver");
        }
    }

    ~c_driver()
    {
        if (is_driver_open())
        {
            close(fd);
        }
    }

    bool initialize(pid_t pid)
    {
        if (!is_driver_open())
        {
            fprintf(stderr, "[-] Driver not open\n");
            return false;
        }
        this->pid = pid;
        return true;
    }

    bool read(uintptr_t addr, void *buffer, size_t size)
    {
        if (!is_driver_open())
            return false;

        COPY_MEMORY cm = {pid, addr, buffer, size};

        if (ioctl(fd, OP_READ_MEM, &cm) != 0)
        {
            perror("[-] Failed to read memory");
            return false;
        }
        return true;
    }

    bool write(uintptr_t addr, const void *buffer, size_t size)
    {
        if (!is_driver_open())
            return false;

        COPY_MEMORY cm = {pid, addr, const_cast<void *>(buffer), size};

        if (ioctl(fd, OP_WRITE_MEM, &cm) != 0)
        {
            perror("[-] Failed to write memory");
            return false;
        }
        return true;
    }

    template <typename T>
    T read(uintptr_t addr)
    {
        T result{};
        if (this->read(addr, &result, sizeof(T)))
            return result;
        return result;
    }

    template <typename T>
    bool write(uintptr_t addr, const T &value)
    {
        return this->write(addr, &value, sizeof(T));
    }

    uintptr_t get_module_base(const char *name)
    {
        if (!is_driver_open())
            return 0;

        MODULE_BASE mb = {pid, "", 0};
        strncpy(mb.name, name, sizeof(mb.name) - 1);

        if (ioctl(fd, OP_MODULE_BASE, &mb) != 0)
        {
            perror("[-] Failed to get module base");
            return 0;
        }
        return mb.base;
    }
};