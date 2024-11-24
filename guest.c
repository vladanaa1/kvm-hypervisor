#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>

// File access mode constants
#define O_RDONLY        0
#define O_WRONLY        1
#define O_RDWR          2
#define O_CREAT         64
#define O_TRUNC         512
#define O_APPEND        1024

// Constants for parallel port operations
#define PARALLEL_PORT 0x278
#define OPEN 1
#define CLOSE 2
#define READ 3
#define WRITE 4
#define FINISH 0
#define EOF -1

/**
 * Receives a 32-bit value from a specified port.
 *
 * @param port Port number.
 * @return 32-bit value received from the port.
 */
static int in(uint16_t port) {
    int ret;
    asm("in %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

/**
 * Receives a byte (8 bits) from a specified port.
 *
 * @param port Port number.
 * @return Byte received from the port.
 */
static char inb(uint16_t port) {
    char ret;
    asm("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

/**
 * Sends a 32-bit value to a specified port.
 *
 * @param port Port number.
 * @param value 32-bit value to send to the port.
 */
static void out(uint16_t port, uint32_t value) {
    asm("out %0, %1" : : "a"(value), "Nd" (port) : "memory");
}

/**
 * Sends a byte (8 bits) to a specified port.
 *
 * @param port Port number.
 * @param value Byte to send to the port.
 */
static void outb(uint16_t port, uint8_t value) {
    asm("outb %0,%1" : : "a" (value), "Nd" (port) : "memory");
}

// Halts the CPU indefinitely
static inline void exit() {
    for (;;) {
        asm volatile("hlt");
    }
}

/**
 * Opens a file by sending the filename, flags, and mode to the parallel port.
 *
 * @param file_name Name of the file to open.
 * @param flags Flags for file access mode.
 * @param mode Mode for file creation.
 * @return File descriptor on success, -1 on failure.
 */
static int open(const char* file_name, int flags, int mode) {
    out(PARALLEL_PORT, OPEN); // Indicate OPEN operation
    for (int i = 0; file_name[i]; i++) {
        outb(PARALLEL_PORT, file_name[i]); // Send each character of the filename
    }
    outb(PARALLEL_PORT, '\0'); // Send null terminator

    out(PARALLEL_PORT, flags); // Send file flags
    out(PARALLEL_PORT, mode); // Send file mode

    return in(PARALLEL_PORT); // Receive file descriptor
}

/**
 * Closes a file by sending the file descriptor to the parallel port.
 *
 * @param fd File descriptor of the file to close.
 * @return Status code from the close operation.
 */
static int close(int fd) {
    out(PARALLEL_PORT, CLOSE); // Indicate CLOSE operation
    out(PARALLEL_PORT, fd); // Send file descriptor

    int status = in(PARALLEL_PORT); // Receive status code
    out(PARALLEL_PORT, FINISH); // Indicate operation finish
    return status; // Return status code
}

/**
 * Reads data from a file by sending the file descriptor and receiving the data from the parallel port.
 *
 * @param fd File descriptor of the file to read from.
 * @param buf Buffer to store the read data.
 * @param count Number of bytes to read.
 * @return Number of bytes read.
 */
size_t read(int fd, void* buf, size_t count) {
    char* my_buf = (char*) buf; // Cast buffer to char pointer

    out(PARALLEL_PORT, READ); // Indicate READ operation
    out(PARALLEL_PORT, fd); // Send file descriptor

    size_t ret = 0; // Initialize byte counter
    for (int i = 0; i < count; i++) {
        char c = inb(PARALLEL_PORT); // Receive a byte
        if (c == EOF) break; // Break if end-of-file

        my_buf[i] = c; // Store the byte in the buffer
        ret++; // Increment byte counter
    }

    out(PARALLEL_PORT, FINISH); // Indicate operation finish
    return ret; // Return number of bytes read
}

/**
 * Writes data to a file by sending the file descriptor and the data to the parallel port.
 *
 * @param fd File descriptor of the file to write to.
 * @param buf Buffer containing the data to write.
 * @param count Number of bytes to write.
 * @return Number of bytes written.
 */
size_t write(int fd, void* buf, size_t count) {
    char* my_buf = (char*) buf; // Cast buffer to char pointer

    out(PARALLEL_PORT, WRITE); // Indicate WRITE operation
    out(PARALLEL_PORT, fd); // Send file descriptor

    size_t ret = 0; // Initialize byte counter
    for (int i = 0; i < count; i++) {
        outb(PARALLEL_PORT, my_buf[i]); // Send each byte
        ret++; // Increment byte counter
    }

    out(PARALLEL_PORT, FINISH); // Indicate operation finish
    return ret; // Return number of bytes written
}

// Array of hexadecimal digit characters
static char digits[] = "0123456789ABCDEF";

/**
 * Receives a character from the port 0xE9.
 *
 * @return The received character.
 */
static char getchar() {
    return inb(0xE9); // Use inb to get a character from port 0xE9
}

/**
 * Scans an integer from the input received from the port 0xE9.
 *
 * @return The scanned integer.
 */
int scan_int() {
    char c; // Character read from input
    int num = 0; // The integer being constructed

    // Read characters until a newline is encountered
    while ((c = getchar()) != '\n') {
        num *= 10; // Shift the current number left by one decimal place
        num += c - '0'; // Add the new digit to the number
    }

    return num; // Return the constructed integer
}

/**
 * Sends a character to a file descriptor by writing to the port 0xE9 or using the write function.
 *
 * @param fd File descriptor.
 * @param c Character to be sent.
 */
static void putc(int fd, char c) {
    if (fd == 1) {
        outb(0xE9, c); // Send character 'c' to port 0xE9 for standard output
    } else {
        write(fd, &c, 1); // Write character to file descriptor
    }
}

/**
 * Prints an integer in the specified base to a file descriptor.
 *
 * @param fd File descriptor.
 * @param xx Integer to be printed.
 * @param base Number base (e.g., 10 for decimal, 16 for hexadecimal).
 * @param sgn Indicates whether the number is signed.
 */
static void printint(int fd, int xx, int base, int sgn) {
    char buf[16]; // Buffer to hold the number string
    int i, neg; // 'i' is the buffer index, 'neg' is the negative flag
    uint32_t x; // Unsigned version of the number

    neg = 0; // Assume the number is non-negative initially
    if (sgn && xx < 0) { // Check if the number is signed and negative
        neg = 1; // Set the negative flag
        x = -xx; // Convert to positive
    } else {
        x = xx; // Use the number as-is if it's non-negative
    }

    i = 0; // Initialize buffer index
    do {
        buf[i++] = digits[x % base]; // Convert the least significant digit to a character
    } while ((x /= base) != 0); // Repeat until all digits are processed

    if (neg) {
        buf[i++] = '-'; // Add the negative sign if necessary
    }

    while (--i >= 0) {
        putc(fd, buf[i]); // Output the characters in reverse order
    }
}

/**
 * Prints a pointer value in hexadecimal format to a file descriptor.
 *
 * @param fd File descriptor.
 * @param x Pointer value to be printed.
 */
static void printptr(int fd, uint64_t x) {
    putc(fd, '0'); // Print '0'
    putc(fd, 'x'); // Print 'x' to indicate hexadecimal format
    for (int i = 0; i < (sizeof(uint64_t) * 2); i++, x <<= 4) {
        // Print each nibble (4 bits) of the pointer value
        putc(fd, digits[x >> (sizeof(uint64_t) * 8 - 4)]);
    }
}

/**
 * Prints a formatted string to a file descriptor using a variable argument list.
 *
 * @param fd File descriptor.
 * @param fmt Format string.
 * @param ap Variable argument list.
 */
void vprintf(int fd, const char *fmt, va_list ap) {
    char *s; // Pointer for strings
    int c, state; // 'c' is the current character, 'state' tracks format state

    state = 0; // Initial state (no format specifier)
    for (int i = 0; fmt[i]; i++) {
        c = fmt[i] & 0xff; // Get the current character
        if (state == 0) {
            if (c == '%') {
                state = '%'; // Enter format specifier state
            } else {
                putc(fd, c); // Print regular characters
            }
        } else if (state == '%') {
            if (c == 'd') {
                printint(fd, va_arg(ap, int), 10, 1); // Print signed decimal integer
            } else if (c == 'l') {
                printint(fd, va_arg(ap, uint64_t), 10, 0); // Print unsigned long integer
            } else if (c == 'x') {
                printint(fd, va_arg(ap, int), 16, 0); // Print unsigned hexadecimal integer
            } else if (c == 'p') {
                printptr(fd, va_arg(ap, uint64_t)); // Print pointer
            } else if (c == 's') {
                s = va_arg(ap, char*); // Get string argument
                if (s == 0) {
                    s = "(null)"; // Handle null strings
                }
                while (*s != 0) {
                    putc(fd, *s); // Print each character in the string
                    s++;
                }
            } else if (c == 'c') {
                putc(fd, va_arg(ap, uint32_t)); // Print character
            } else if (c == '%') {
                putc(fd, c); // Print '%' character
            } else {
                putc(fd, '%'); // Print unknown format specifier as is
                putc(fd, c);
            }
            state = 0; // Reset state after processing format specifier
        }
    }
}

/**
 * Prints a formatted string to a file descriptor using a variable argument list.
 *
 * @param fd File descriptor.
 * @param fmt Format string.
 * @param ... Variable arguments.
 */
void fprintf(int fd, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt); // Initialize the variable argument list
    vprintf(fd, fmt, ap); // Call vprintf to handle the formatted output
    va_end(ap); // Clean up the variable argument list
}

/**
 * Prints a formatted string using a variable argument list.
 *
 * @param fmt Format string.
 * @param ... Variable arguments.
 */
void printf(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt); // Initialize the variable argument list
    vprintf(1, fmt, ap); // Call vprintf to handle the formatted output to standard output
    va_end(ap); // Clean up the variable argument list
}

/**
 * Entry point of the program. Initializes the CPU state, performs file operations, and prints results.
 */
void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
    // Open the file "primer.txt" in read-only mode
    int fd = open("primer.txt", O_RDONLY, 0);
    printf("%d\n", fd); // Print the file descriptor
    if (fd < 0) {
        printf("Error opening file\n");
        exit(); // Exit if file opening fails
    }

    char buf[20]; // Buffer to store read data
    size_t size; // Size of data read

    // Read data from the file and print it until the end of the file
    do {
        size = read(fd, buf, 20);
        printf("SIZE: %d", size); // Print the size of data read
        for (int i = 0; i < size; i++) {
            printf("%c", buf[i]); // Print each character read from the file
        }
    } while (size == 20);

    // Open the file "out.txt" in write-only mode with full permissions
    fd = open("out.txt", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    printf("%d\n", fd); // Print the file descriptor
    if (fd < 0) {
        printf("Error opening file\n");
        exit(); // Exit if file opening fails
    }

    // Write the data read from the first file to the second file
    write(fd, buf, size);

    // Close the second file
    close(fd);

    // Halts the CPU indefinitely
    for (;;) {
        asm volatile("hlt");
    }
}
