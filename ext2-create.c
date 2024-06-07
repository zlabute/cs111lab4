#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int16_t i16;
typedef int32_t i32;

#define BLOCK_SIZE 1024
#define BLOCK_OFFSET(i) (i * BLOCK_SIZE)
#define NUM_BLOCKS 1024
#define NUM_INODES 128

#define LOST_AND_FOUND_INO 11
#define HELLO_WORLD_INO    12
#define HELLO_INO          13
#define LAST_INO           HELLO_INO

#define SUPERBLOCK_BLOCKNO             1
#define BLOCK_GROUP_DESCRIPTOR_BLOCKNO 2
#define BLOCK_BITMAP_BLOCKNO           3
#define INODE_BITMAP_BLOCKNO           4
#define INODE_TABLE_BLOCKNO            5
#define ROOT_DIR_BLOCKNO               21
#define LOST_AND_FOUND_DIR_BLOCKNO     22
#define HELLO_WORLD_FILE_BLOCKNO       23
#define LAST_BLOCK                     HELLO_WORLD_FILE_BLOCKNO

#define NUM_FREE_BLOCKS (NUM_BLOCKS - LAST_BLOCK - 1)
#define NUM_FREE_INODES (NUM_INODES - LAST_INO)

#define EXT2_SUPER_MAGIC 0xEF53

/* http://www.nongnu.org/ext2-doc/ext2.html */
/* http://www.science.smith.edu/~nhowe/262/oldlabs/ext2.html */

#define EXT2_BAD_INO             1
#define EXT2_ROOT_INO            2
#define EXT2_GOOD_OLD_FIRST_INO  11

#define EXT2_GOOD_OLD_REV 0

#define EXT2_S_IFSOCK 0xC000
#define EXT2_S_IFLNK  0xA000
#define EXT2_S_IFREG  0x8000
#define EXT2_S_IFBLK  0x6000
#define EXT2_S_IFDIR  0x4000
#define EXT2_S_IFCHR  0x2000
#define EXT2_S_IFIFO  0x1000
#define EXT2_S_ISUID  0x0800
#define EXT2_S_ISGID  0x0400
#define EXT2_S_ISVTX  0x0200
#define EXT2_S_IRUSR  0x0100
#define EXT2_S_IWUSR  0x0080
#define EXT2_S_IXUSR  0x0040
#define EXT2_S_IRGRP  0x0020
#define EXT2_S_IWGRP  0x0010
#define EXT2_S_IXGRP  0x0008
#define EXT2_S_IROTH  0x0004
#define EXT2_S_IWOTH  0x0002
#define EXT2_S_IXOTH  0x0001

#define EXT2_NDIR_BLOCKS 12
#define EXT2_IND_BLOCK   EXT2_NDIR_BLOCKS
#define EXT2_DIND_BLOCK  (EXT2_IND_BLOCK + 1)
#define EXT2_TIND_BLOCK  (EXT2_DIND_BLOCK + 1)
#define EXT2_N_BLOCKS    (EXT2_TIND_BLOCK + 1)

#define EXT2_NAME_LEN 255

struct ext2_superblock {
    u32 s_inodes_count;
    u32 s_blocks_count;
    u32 s_r_blocks_count;
    u32 s_free_blocks_count;
    u32 s_free_inodes_count;
    u32 s_first_data_block;
    u32 s_log_block_size;
    i32 s_log_frag_size;
    u32 s_blocks_per_group;
    u32 s_frags_per_group;
    u32 s_inodes_per_group;
    u32 s_mtime;
    u32 s_wtime;
    u16 s_mnt_count;
    i16 s_max_mnt_count;
    u16 s_magic;
    u16 s_state;
    u16 s_errors;
    u16 s_minor_rev_level;
    u32 s_lastcheck;
    u32 s_checkinterval;
    u32 s_creator_os;
    u32 s_rev_level;
    u16 s_def_resuid;
    u16 s_def_resgid;
    u32 s_pad[5];
    u8 s_uuid[16];
    u8 s_volume_name[16];
    u32 s_reserved[229];
};

struct ext2_block_group_descriptor {
    u32 bg_block_bitmap;
    u32 bg_inode_bitmap;
    u32 bg_inode_table;
    u16 bg_free_blocks_count;
    u16 bg_free_inodes_count;
    u16 bg_used_dirs_count;
    u16 bg_pad;
    u32 bg_reserved[3];
};

struct ext2_inode {
    u16 i_mode;
    u16 i_uid;
    u32 i_size;
    u32 i_atime;
    u32 i_ctime;
    u32 i_mtime;
    u32 i_dtime;
    u16 i_gid;
    u16 i_links_count;
    u32 i_blocks;
    u32 i_flags;
    u32 i_reserved1;
    u32 i_block[EXT2_N_BLOCKS];
    u32 i_version;
    u32 i_file_acl;
    u32 i_dir_acl;
    u32 i_faddr;
    u8  i_frag;
    u8  i_fsize;
    u16 i_pad1;
    u32 i_reserved2[2];
};

struct ext2_dir_entry {
    u32 inode;
    u16 rec_len;
    u16 name_len;
    u8  name[EXT2_NAME_LEN];
};

#define errno_exit(str)                                                        \
    do { int err = errno; perror(str); exit(err); } while (0)

#define dir_entry_set(entry, inode_num, str)                                   \
    do {                                                                       \
        const char *s = str;                                                   \
        size_t len = strlen(s);                                                \
        entry.inode = inode_num;                                               \
        entry.name_len = len;                                                  \
        memcpy(&entry.name, s, len);                                           \
        entry.rec_len = 8 + len + (4 - len % 4) % 4;                           \
    } while (0)

#define dir_entry_write(entry, fd)                                             \
    do {                                                                       \
        size_t size = entry.rec_len;                                           \
        if (write(fd, &entry, size) != size) {                                 \
            errno_exit("write");                                               \
        }                                                                      \
    } while (0)

u32 get_current_time() {
    time_t t = time(NULL);
    if (t == ((time_t) -1)) {
        errno_exit("time");
    }
    return t;
}

void write_superblock(int fd) {
    off_t off = lseek(fd, BLOCK_OFFSET(1), SEEK_SET);
    if (off == -1) {
        errno_exit("lseek");
    }

    u32 current_time = get_current_time();

    struct ext2_superblock superblock = {0};

    superblock.s_inodes_count      = NUM_INODES;  // GOOD
    superblock.s_blocks_count      = NUM_BLOCKS;  // GOOD
    superblock.s_r_blocks_count    = 0; // reserved blocks // GOOD
    superblock.s_free_blocks_count = NUM_FREE_BLOCKS; // GOOD
    superblock.s_free_inodes_count = NUM_FREE_INODES; // GOOD
    superblock.s_first_data_block  = SUPERBLOCK_BLOCKNO; /* First Data Block */ // GOOD
    superblock.s_log_block_size    = 0;                 /* 1024 */ // GOOD
    superblock.s_log_frag_size     = 0;                 /* 1024 */ // GOOD
    superblock.s_blocks_per_group  = NUM_BLOCKS; // GOOD
    superblock.s_frags_per_group   = NUM_BLOCKS; // GOOD
    superblock.s_inodes_per_group  = NUM_INODES; // GOOD
    superblock.s_mtime             = 0;                 /* Mount time */ // GOOD
    superblock.s_wtime             = current_time;      /* Write time */ // GOOD
    superblock.s_mnt_count         = 0; /* Number of times mounted so far */ // GOOD
    superblock.s_max_mnt_count     = -1; /* Make this unlimited */ // GOOD
    superblock.s_magic             = 0xEF53; /* ext2 Signature */ // GOOD
    superblock.s_state             = 1; /* File system is clean */ // GOOD
    superblock.s_errors            = 1; /* Ignore the error (continue on) */ // GOOD
    superblock.s_minor_rev_level   = 0; /* Leave this as 0 */
    superblock.s_lastcheck         = current_time; /* Last check time */
    superblock.s_checkinterval     = 1; /* Force checks by making them every 1 second */ // GOOD
    superblock.s_creator_os        = 0; /* Linux */ // GOOD
    superblock.s_rev_level         = 0; /* Leave this as 0 */ // GOOD
    superblock.s_def_resuid        = 0; /* root */ // GOOD
    superblock.s_def_resgid        = 0; /* root */ // GOOD

    memcpy(&superblock.s_uuid, "\x5A\x1E\xAB\x1E\x13\x37\x13\x37\x13\x37\xC0\xFF\xEE\xC0\xFF\xEE", 16);
    memcpy(&superblock.s_volume_name, "cs111-base", 10);

    ssize_t size = sizeof(superblock);
    if (write(fd, &superblock, size) != size) {
        errno_exit("write");
    }
}

void write_block_group_descriptor_table(int fd) {
    off_t off = lseek(fd, BLOCK_OFFSET(BLOCK_GROUP_DESCRIPTOR_BLOCKNO), SEEK_SET);
    if (off == -1) {
        errno_exit("lseek");
    }

    struct ext2_block_group_descriptor block_group_descriptor = {0};

    block_group_descriptor.bg_block_bitmap = BLOCK_BITMAP_BLOCKNO; // GOOD
    block_group_descriptor.bg_inode_bitmap = INODE_BITMAP_BLOCKNO; // GOOD
    block_group_descriptor.bg_inode_table = INODE_TABLE_BLOCKNO; // GOOD
    block_group_descriptor.bg_free_blocks_count = NUM_FREE_BLOCKS; // GOOD
    block_group_descriptor.bg_free_inodes_count = NUM_FREE_INODES; // GOOD
    block_group_descriptor.bg_used_dirs_count = 2; // GOOD

    ssize_t size = sizeof(block_group_descriptor);
    if (write(fd, &block_group_descriptor, size) != size) {
        errno_exit("write");
    }
}

void write_bit_byte(u8 *map_value, u32 n) {
    u32 byte_num = (n - 1) / 8;
    u32 bit_num = (n - 1) % 8;
    map_value[byte_num] |= (1 << bit_num);
}

void write_block_bitmap(int fd) {
    off_t off = lseek(fd, BLOCK_OFFSET(BLOCK_BITMAP_BLOCKNO), SEEK_SET);
    if (off == -1) {
        errno_exit("lseek");
    }

    u8 map_value[BLOCK_SIZE] = {0x00}; // creates a map of bits array of size 128 bytes

    for (u32 i = 1; i <= LAST_BLOCK; i++) {
        write_bit_byte(map_value, i);
    }

    ssize_t size = sizeof(map_value); // write the map_value to file descriptor

    if (write(fd, map_value, size) != BLOCK_SIZE) {
        errno_exit("write");
    }
}

void write_inode_bitmap(int fd) {
    off_t off = lseek(fd, BLOCK_OFFSET(INODE_BITMAP_BLOCKNO), SEEK_SET);
    if (off == -1) {
        errno_exit("lseek");
    }

    u8 map_value[BLOCK_SIZE] = {0x00}; // make another array of 128 bytes

    for (u32 i = 1; i <= LAST_INO; i++) {
        write_bit_byte(map_value, i);
    }

    ssize_t size = sizeof(map_value);

    if (write(fd, map_value, size) != BLOCK_SIZE) { // write the map_value array to file descriptor 
        errno_exit("write");
    }
}

void write_inode(int fd, u32 index, struct ext2_inode *inode) {
    off_t off = BLOCK_OFFSET(INODE_TABLE_BLOCKNO) + (index - 1) * sizeof(struct ext2_inode);
    off = lseek(fd, off, SEEK_SET);
    if (off == -1) {
        errno_exit("lseek");
    }

    ssize_t size = sizeof(struct ext2_inode);
    if (write(fd, inode, size) != size) {
        errno_exit("write");
    }
}

void write_inode_table(int fd) {
    u32 current_time = get_current_time();

    struct ext2_inode lost_and_found_inode = {0};
    lost_and_found_inode.i_mode = EXT2_S_IFDIR
                                  | EXT2_S_IRUSR
                                  | EXT2_S_IWUSR
                                  | EXT2_S_IXUSR
                                  | EXT2_S_IRGRP
                                  | EXT2_S_IXGRP
                                  | EXT2_S_IROTH
                                  | EXT2_S_IXOTH;
    lost_and_found_inode.i_uid = 0;
    lost_and_found_inode.i_size = 1024;
    lost_and_found_inode.i_atime = current_time;
    lost_and_found_inode.i_ctime = current_time;
    lost_and_found_inode.i_mtime = current_time;
    lost_and_found_inode.i_dtime = 0;
    lost_and_found_inode.i_gid = 0;
    lost_and_found_inode.i_links_count = 2;
    lost_and_found_inode.i_blocks = 2; /* These are oddly 512 blocks */
    lost_and_found_inode.i_block[0] = LOST_AND_FOUND_DIR_BLOCKNO;
    write_inode(fd, LOST_AND_FOUND_INO, &lost_and_found_inode);

    struct ext2_inode hello_world_inode = {0};
    hello_world_inode.i_mode       = EXT2_S_IFREG | EXT2_S_IRUSR | EXT2_S_IWUSR | EXT2_S_IRGRP | EXT2_S_IROTH;
    hello_world_inode.i_size       = 12;
    hello_world_inode.i_uid        = 1000;
    hello_world_inode.i_atime      = current_time;
    hello_world_inode.i_ctime      = current_time;
    hello_world_inode.i_mtime      = current_time;
    hello_world_inode.i_dtime      = 0;
    hello_world_inode.i_gid        = 1000;
    hello_world_inode.i_links_count = 1; 
    hello_world_inode.i_blocks     = 2; 
    hello_world_inode.i_block[0]   = HELLO_WORLD_FILE_BLOCKNO;
    write_inode(fd, HELLO_WORLD_INO, &hello_world_inode);

    struct ext2_inode hello_inode = {0};
    hello_inode.i_mode = EXT2_S_IFLNK | EXT2_S_IRUSR | EXT2_S_IWUSR | EXT2_S_IRGRP | EXT2_S_IROTH;
    hello_inode.i_uid = 1000;
    hello_inode.i_atime = current_time; 
    hello_inode.i_ctime = current_time;
    hello_inode.i_mtime = current_time;
    hello_inode.i_dtime = 0;
    hello_inode.i_gid    = 1000;
    hello_inode.i_links_count = 1;
    hello_inode.i_blocks = 0;
    hello_inode.i_size = strlen("hello-world");
    memcpy(hello_inode.i_block, "hello-world", strlen("hello-world"));
    write_inode(fd, HELLO_INO, &hello_inode);

    struct ext2_inode root_inode = {0};
    root_inode.i_mode = EXT2_S_IFDIR | EXT2_S_IRUSR | EXT2_S_IWUSR | EXT2_S_IXUSR | EXT2_S_IRGRP | EXT2_S_IXGRP | EXT2_S_IROTH | EXT2_S_IXOTH;
    root_inode.i_size = 1024;
    root_inode.i_uid = 0;
    root_inode.i_atime = current_time;
    root_inode.i_ctime = current_time;
    root_inode.i_mtime = current_time;
    root_inode.i_dtime = 0;
    root_inode.i_gid = 0;
    root_inode.i_links_count = 2;
    root_inode.i_blocks = 2;
    root_inode.i_block[0] = ROOT_DIR_BLOCKNO;
    write_inode(fd, EXT2_ROOT_INO, &root_inode);
}

void write_root_dir_block(int fd) {
    off_t off = lseek(fd, BLOCK_OFFSET(ROOT_DIR_BLOCKNO), SEEK_SET);
    if (off == -1) {
        errno_exit("lseek");
    }

    ssize_t bytes_remaining = BLOCK_SIZE;

    struct ext2_dir_entry current_entry = {0};
    dir_entry_set(current_entry, EXT2_ROOT_INO, ".");
    dir_entry_write(current_entry, fd);
    bytes_remaining -= current_entry.rec_len;

    struct ext2_dir_entry parent_entry = {0};
    dir_entry_set(parent_entry, EXT2_ROOT_INO, "..");
    dir_entry_write(parent_entry, fd);
    bytes_remaining -= parent_entry.rec_len;

    struct ext2_dir_entry lost_and_found_entry = {0};
    dir_entry_set(lost_and_found_entry, LOST_AND_FOUND_INO, "lost+found");
    dir_entry_write(lost_and_found_entry, fd);
    bytes_remaining -= lost_and_found_entry.rec_len;

    struct ext2_dir_entry hello_entry = {0};
    dir_entry_set(hello_entry, HELLO_INO, "hello");
    dir_entry_write(hello_entry, fd);
    bytes_remaining -= hello_entry.rec_len;

    struct ext2_dir_entry hello_world_entry = {0};
    dir_entry_set(hello_world_entry, HELLO_WORLD_INO, "hello-world");
    dir_entry_write(hello_world_entry, fd);
    bytes_remaining -= hello_world_entry.rec_len;

    struct ext2_dir_entry fill_entry = {0};
    fill_entry.rec_len = bytes_remaining;
    dir_entry_write(fill_entry, fd);
}

void write_lost_and_found_dir_block(int fd) {
    off_t off = lseek(fd, BLOCK_OFFSET(LOST_AND_FOUND_DIR_BLOCKNO), SEEK_SET);
    if (off == -1) {
        errno_exit("lseek");
    }

    ssize_t bytes_remaining = BLOCK_SIZE;

    struct ext2_dir_entry current_entry = {0};
    dir_entry_set(current_entry, LOST_AND_FOUND_INO, ".");
    dir_entry_write(current_entry, fd);
    bytes_remaining -= current_entry.rec_len;

    struct ext2_dir_entry parent_entry = {0};
    dir_entry_set(parent_entry, EXT2_ROOT_INO, "..");
    dir_entry_write(parent_entry, fd);
    bytes_remaining -= parent_entry.rec_len;

    struct ext2_dir_entry fill_entry = {0};
    fill_entry.rec_len = bytes_remaining;
    dir_entry_write(fill_entry, fd);
}

void write_hello_world_file_block(int fd) {
    off_t off = lseek(fd, BLOCK_OFFSET(HELLO_WORLD_FILE_BLOCKNO), SEEK_SET);
    if (off == -1) {
        errno_exit("lseek");
    }

    char const text[] = "Hello world\n";
    ssize_t size = sizeof(text) - 1;
    if (write(fd, text, size) != size) {
        errno_exit("write");
    }
}

int main(int argc, char *argv[]) {
    int fd = open("cs111-base.img", O_CREAT | O_WRONLY, 0666);
    if (fd == -1) {
        errno_exit("open");
    }

    if (ftruncate(fd, 0)) {
        errno_exit("ftruncate");
    }
    if (ftruncate(fd, NUM_BLOCKS * BLOCK_SIZE)) {
        errno_exit("ftruncate");
    }

    write_superblock(fd);
    write_block_group_descriptor_table(fd);
    write_block_bitmap(fd);
    write_inode_bitmap(fd);
    write_inode_table(fd);
    write_root_dir_block(fd);
    write_lost_and_found_dir_block(fd);
    write_hello_world_file_block(fd);

    if (close(fd)) {
        errno_exit("close");
    }
    return 0;
}
