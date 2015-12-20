#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define STX 0x7E
#define CR  0x0D
#define hexchar(ch) (ch & 0xff)

int sockfd, portno, n;
struct sockaddr_in serv_addr;
struct hostent *server;



const unsigned char ProtocolCrc16Table1[] =
{
   0x00, 0xc0, 0xc1, 0x01, 0xc3, 0x03, 0x02, 0xc2, 0xc6, 0x06, 0x07, 0xc7, 0x05, 0xc5, 0xc4, 0x04,
   0xcc, 0x0c, 0x0d, 0xcd, 0x0f, 0xcf, 0xce, 0x0e, 0x0a, 0xca, 0xcb, 0x0b, 0xc9, 0x09, 0x08, 0xc8,
   0xd8, 0x18, 0x19, 0xd9, 0x1b, 0xdb, 0xda, 0x1a, 0x1e, 0xde, 0xdf, 0x1f, 0xdd, 0x1d, 0x1c, 0xdc,
   0x14, 0xd4, 0xd5, 0x15, 0xd7, 0x17, 0x16, 0xd6, 0xd2, 0x12, 0x13, 0xd3, 0x11, 0xd1, 0xd0, 0x10,
   0xf0, 0x30, 0x31, 0xf1, 0x33, 0xf3, 0xf2, 0x32, 0x36, 0xf6, 0xf7, 0x37, 0xf5, 0x35, 0x34, 0xf4,
   0x3c, 0xfc, 0xfd, 0x3d, 0xff, 0x3f, 0x3e, 0xfe, 0xfa, 0x3a, 0x3b, 0xfb, 0x39, 0xf9, 0xf8, 0x38,
   0x28, 0xe8, 0xe9, 0x29, 0xeb, 0x2b, 0x2a, 0xea, 0xee, 0x2e, 0x2f, 0xef, 0x2d, 0xed, 0xec, 0x2c,
   0xe4, 0x24, 0x25, 0xe5, 0x27, 0xe7, 0xe6, 0x26, 0x22, 0xe2, 0xe3, 0x23, 0xe1, 0x21, 0x20, 0xe0,
   0xa0, 0x60, 0x61, 0xa1, 0x63, 0xa3, 0xa2, 0x62, 0x66, 0xa6, 0xa7, 0x67, 0xa5, 0x65, 0x64, 0xa4,
   0x6c, 0xac, 0xad, 0x6d, 0xaf, 0x6f, 0x6e, 0xae, 0xaa, 0x6a, 0x6b, 0xab, 0x69, 0xa9, 0xa8, 0x68,
   0x78, 0xb8, 0xb9, 0x79, 0xbb, 0x7b, 0x7a, 0xba, 0xbe, 0x7e, 0x7f, 0xbf, 0x7d, 0xbd, 0xbc, 0x7c,
   0xb4, 0x74, 0x75, 0xb5, 0x77, 0xb7, 0xb6, 0x76, 0x72, 0xb2, 0xb3, 0x73, 0xb1, 0x71, 0x70, 0xb0,
   0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54,
   0x9c, 0x5c, 0x5d, 0x9d, 0x5f, 0x9f, 0x9e, 0x5e, 0x5a, 0x9a, 0x9b, 0x5b, 0x99, 0x59, 0x58, 0x98,
   0x88, 0x48, 0x49, 0x89, 0x4b, 0x8b, 0x8a, 0x4a, 0x4e, 0x8e, 0x8f, 0x4f, 0x8d, 0x4d, 0x4c, 0x8c,
  0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83, 0x41, 0x81, 0x80, 0x40
} ;

const unsigned char ProtocolCrc16Table2[] =
{
   0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41, 0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40,
   0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40, 0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41,
   0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40, 0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41,
   0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41, 0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40,
   0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40, 0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41,
   0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41, 0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40,
   0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41, 0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40,
   0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40, 0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41,
   0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40, 0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41,
   0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41, 0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40,
   0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41, 0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40,
   0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40, 0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41,
   0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41, 0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40,
   0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40, 0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41,
   0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40, 0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41,
  0x00, 0xc1, 0x81, 0x40, 0x01, 0xc0, 0x80, 0x41, 0x01, 0xc0, 0x80, 0x41, 0x00, 0xc1, 0x81, 0x40
} ;

void ProtocolBufferGetCrc(unsigned char* Buffer, int NumBytes, char* Crc1, char* Crc0)
{
  int TempCnt ;
  unsigned char TempByte ;

  for ( TempCnt = 0 ; TempCnt < NumBytes ; TempCnt++ )
  {
    TempByte = Buffer[TempCnt] ;
    TempByte ^= *Crc0 ;
    TempByte = TempByte;
    *Crc0 = (*Crc1 ^ ProtocolCrc16Table2[TempByte]);
    *Crc1 = ProtocolCrc16Table1[TempByte];
  }
  return;
} //ProtocolBufferGetCrc

int ProtocolBufferCheckCrc(unsigned char *Buffer, int NumBytes)
{
  uint8_t TempCrc0 = 0xFF ;
  uint8_t TempCrc1 = 0xFF ;

  ProtocolBufferGetCrc(Buffer, NumBytes, &TempCrc0, &TempCrc1) ;
  //printf("External CRC : %x %x\n",Buffer[NumBytes],Buffer[NumBytes+1]);
  //printf("Local CRC  : %x %x\n", TempCrc0, TempCrc1);

//printf("the subtractin of crc1 = %d\n", Buffer[NumBytes] - TempCrc0)
  if (((uint8_t)Buffer[NumBytes] == (uint8_t)TempCrc0) && ((uint8_t)Buffer[NumBytes + 1] == (uint8_t)TempCrc1))
  {
    return(1) ; //CRC OK
  }
  else
  {
    return(0) ; //BAD CRC
  }
} //ProtocolBufferCheckCrc




enum addressing_mode{
        ADDR_MODE_PHY = 0x20,
        ADDR_MODE_ID = 0x40,
        ADDR_MODE_ID2ID = 0x60,
        ADDR_MODE_TYPE = 0x80,
        ADDR_MODE_DC = 0xA0,
        ADDR_MODE_BROAD = 0xC0,
}address_mode_t;

enum commands{
        CMD_MAILBOX_READ = 0x01,
        CMD_MAILBOX_WRITE = 0x11,
        CMD_STATUS_READ = 0x02,
        CMD_WORD_READ = 0x04,
        CMD_WORD_WRITE = 0x14,
        CMD_DWORD_READ = 0x06,
        CMD_DWORD_WRITE = 0x16,
        CMD_FLASH_READ = 0x0C,
        CMD_FLASH_WRITE = 0x1C,
        CMD_FLASH_DWORD_READ = 0x0E,
        CMD_FLASH_DWORD_WRITE = 0x1E,
}commands_t;



void  tokenize(char * command, int * arg_count, const char *delim, int max_tokens, char *arg_strings[]){

   int arg_index = 0;

   char *pch;
   pch = strtok(command,delim);
   while(pch != NULL){
        arg_strings[arg_index++] = pch;
        //arg_index++;
        if(arg_index >max_tokens)break;
        pch = strtok(NULL,delim);
   }

   *arg_count = arg_index;

}


int set_cmd_block(char *addr_mode, char* cmd_mode, uint8_t *cmd_block_val){

    uint8_t dec_addr_mode = strtol(addr_mode,NULL,10);
    uint8_t dec_cmd_mode = strtol(cmd_mode,NULL,10);

    uint8_t temp_addr_mode ;
    uint8_t temp_cmd_mode ;

    switch(dec_addr_mode){
        case 0: temp_addr_mode = ADDR_MODE_PHY;break;
        case 1: temp_addr_mode = ADDR_MODE_ID;break;
        case 2: temp_addr_mode = ADDR_MODE_ID2ID;break;
        case 3: temp_addr_mode = ADDR_MODE_TYPE;break;
        case 4: temp_addr_mode = ADDR_MODE_DC;break;
        case 5: temp_addr_mode = ADDR_MODE_BROAD;break;
        default:temp_addr_mode =0;break;
    }


    switch(dec_cmd_mode){
        case 0: temp_cmd_mode = CMD_MAILBOX_READ;break;
        case 1: temp_cmd_mode = CMD_MAILBOX_WRITE;break;
        case 2: temp_cmd_mode = CMD_STATUS_READ;break;
        case 3: temp_cmd_mode = CMD_WORD_READ;break;
        case 4: temp_cmd_mode = CMD_WORD_WRITE;break;
        case 5: temp_cmd_mode = CMD_DWORD_READ;break;
        case 6: temp_cmd_mode = CMD_DWORD_WRITE;break;
        case 7: temp_cmd_mode = CMD_FLASH_READ;break;
        case 8: temp_cmd_mode = CMD_FLASH_WRITE;break;
        case 9: temp_cmd_mode = CMD_FLASH_DWORD_READ;break;
        case 10: temp_cmd_mode = CMD_FLASH_DWORD_WRITE;break;
        default:temp_cmd_mode = 0;break;
    }

    *cmd_block_val =  temp_addr_mode | temp_cmd_mode;
    return sizeof(*cmd_block_val);

}



int set_addressing_block_by_phy(char *addr, uint8_t *phy_addr){
    int myargc;
    char *myargs[6];
    tokenize(addr, &myargc," :",10,myargs);
    int i;
    for(i=0;i<6;i++){
        phy_addr[i] = strtol(myargs[i],NULL,16);
    }
    return 6;
}

int set_addressing_block_by_id(char *id, uint8_t *id_addr){
    uint16_t id_addr_value;
    id_addr_value = strtol(id,NULL,10);

    id_addr[1] = (id_addr_value & 0x00FF) ;
    id_addr[0] = (id_addr_value & 0xFF00)>> 8 ;

    return 2;
}

int set_addressing_block_by_id2id(char *sid, char *id, uint8_t *id2id_addr){

    uint16_t sid_addr_value;
    uint16_t id_addr_value;
    sid_addr_value = strtol(sid,NULL,10);
    id_addr_value = strtol(id,NULL,10);

    id2id_addr[1] = (sid_addr_value & 0x00FF) ;
    id2id_addr[0] = (sid_addr_value & 0xFF00)>> 8 ;
    id2id_addr[3] = (id_addr_value & 0x00FF) ;
    id2id_addr[2] = (id_addr_value & 0xFF00)>> 8 ;

    return 4;
}

int set_addressing_block_by_type(char *type, uint8_t *type_addr){
    uint8_t type_addr_value;
    //id_addr_value = strtol(id,NULL,10);

    //id_addr[0] = (id_addr_value & 0x00FF) ;
    //id_addr[1] = (id_addr_value & 0xFF00)>> 8 ;

    return 1;
}


int set_command_block_mailbox_read(char *len, uint8_t *block){
    block[0] = strtol(len,NULL,10);
    return 1;
}

int set_command_block_status_read(char *addr, char *len, uint8_t *block){
    block[0] = strtol(addr,NULL,10);
    block[1] = strtol(len,NULL,10);
    return 2;
}

int set_command_block_word_read(char *addr, char *len, uint8_t *block){
    uint16_t addr_val = strtol(addr,NULL,10);
    block[1] = ((addr_val & 0x00FF));
    block[0] = ((addr_val & 0xFF00)>>8);
    block[2] = strtol(len,NULL,10);
    return 3;
}

int set_command_block_dword_read(char *addr, char *len, uint8_t *block){
    uint32_t addr_val = strtol(addr,NULL,10);
    block[3] = ((addr_val & 0x000000FF));
    block[2] = ((addr_val & 0x0000FF00)>>8);
    block[1] = ((addr_val & 0x00FF0000)>>16);
    block[0] = ((addr_val & 0xFF000000)>>24);
    block[4] = strtol(len,NULL,10);
    return 5;
}

int set_command_block_flash_word_read(char *addr, char *len, uint8_t *block){
    uint16_t addr_val = strtol(addr,NULL,10);
    block[1] = ((addr_val & 0x00FF));
    block[0] = ((addr_val & 0xFF00)>>8);
    block[2] = strtol(len,NULL,10);
    return 3;
}

int set_command_block_flash_dword_read(char *addr, char *len, uint8_t *block){
    uint32_t addr_val = strtol(addr,NULL,10);
    block[3] = ((addr_val & 0x000000FF));
    block[2] = ((addr_val & 0x0000FF00)>>8);
    block[1] = ((addr_val & 0x00FF0000)>>16);
    block[0] = ((addr_val & 0xFF000000)>>24);
    block[4] = strtol(len,NULL,10);
    return 5;
}


int set_command_block_mailbox_write(char *data, uint8_t *block){
    uint32_t data_val = strtol(data,NULL,10);
    block[3] = ((data_val & 0x000000FF));
    block[2] = ((data_val & 0x0000FF00)>>8);
    block[1] = ((data_val & 0x00FF0000)>>16);
    block[0] = ((data_val & 0xFF000000)>>24);
    return 4;
}

int set_command_block_word_write(char *addr, char *data ,uint8_t *block){
    uint16_t addr_val = strtol(addr,NULL,10);
    uint32_t data_val = strtol(data,NULL,10);
    block[1] = ((addr_val & 0x00FF));
    block[0] = ((addr_val & 0xFF00)>>8);
    block[5] = ((data_val & 0x000000FF));
    block[4] = ((data_val & 0x0000FF00)>>8);
    block[3] = ((data_val & 0x00FF0000)>>16);
    block[2] = ((data_val & 0xFF000000)>>24);

    return 6;
}

int set_command_block_dword_write(char *addr, char *data ,uint8_t *block){
    uint32_t addr_val = strtol(addr,NULL,10);
    uint32_t data_val = strtol(data,NULL,10);
    block[3] = ((addr_val & 0x000000FF));
    block[2] = ((addr_val & 0x0000FF00)>>8);
    block[1] = ((addr_val & 0x00FF0000)>>16);
    block[0] = ((addr_val & 0xFF000000)>>24);
    //block[7] = ((data_val & 0x000000FF));
    //block[6] = ((data_val & 0x0000FF00)>>8);
    //block[5] = ((data_val & 0x00FF0000)>>16);
    //block[4] = ((data_val & 0xFF000000)>>24);
    block[5] = ((data_val & 0x000000FF));
    block[4] = ((data_val & 0x0000FF00)>>8);
    



   // return 8;
    return 6;
}

int set_command_block_flash_word_write(char *addr, char *data ,uint8_t *block){
    uint16_t addr_val = strtol(addr,NULL,10);
    uint32_t data_val = strtol(data,NULL,10);
    block[1] = ((data_val & 0x00FF));
    block[0] = ((data_val & 0xFF00)>>8);
    block[5] = ((addr_val & 0x000000FF));
    block[4] = ((addr_val & 0x0000FF00)>>8);
    block[3] = ((addr_val & 0x00FF0000)>>16);
    block[2] = ((addr_val & 0xFF000000)>>24);

    return 6;
}

int set_command_block_flash_dword_write(char *addr, char *data ,uint8_t *block){
    uint32_t addr_val = strtol(addr,NULL,10);
    uint32_t data_val = strtol(data,NULL,10);
    block[3] = ((addr_val & 0x000000FF));
    block[2] = ((addr_val & 0x0000FF00)>>8);
    block[1] = ((addr_val & 0x00FF0000)>>16);
    block[0] = ((addr_val & 0xFF000000)>>24);
    block[7] = ((data_val & 0x000000FF));
    block[6] = ((data_val & 0x0000FF00)>>8);
    block[5] = ((data_val & 0x00FF0000)>>16);
    block[4] = ((data_val & 0xFF000000)>>24);

   	 return 8;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////

int create_addressing_block(char *addr_mode, char *addr_string, char *addr2_string, uint8_t *addr_block){
    int addr_mode_val = strtol(addr_mode,NULL,10);
    switch(addr_mode_val){
        case 0: return set_addressing_block_by_phy(addr_string, addr_block);break;
        case 1: return set_addressing_block_by_id(addr_string, addr_block);break;
        case 2: return set_addressing_block_by_id2id(addr2_string,addr_string,addr_block);break;
        //case 3: return set_addressing_block_by_type(addr_string,addr_block);break; //INCOMPLETE
        default: return 0;break;
    }
}

int create_command_block(char *cmd_mode,char* addr, char * len, char* data, uint8_t *addr_block){

    int cmd_mode_val = strtol(cmd_mode,NULL,10);
    switch(cmd_mode_val){
        case 0 :return set_command_block_mailbox_read(len,addr_block);break;
        case 1 :return set_command_block_mailbox_write(data,addr_block);break;
        case 2 :return set_command_block_status_read(addr,len,addr_block);break;
        case 3 :return set_command_block_word_read(addr,len,addr_block);break;
        case 4 :return set_command_block_word_write(addr,data,addr_block);break;
        case 5 :return set_command_block_dword_read(addr,len,addr_block);break;
        case 6 :return set_command_block_dword_write(addr,data,addr_block);break;
        case 7 :return set_command_block_flash_word_read(addr,len,addr_block);break;
        case 8 :return set_command_block_flash_word_write(addr,len,addr_block);break;
        case 9 :return set_command_block_flash_dword_read(addr,len,addr_block);break;
        case 10 :return set_command_block_flash_dword_write(addr,len,addr_block);break;
        default:return 0; break;
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////

void error(const char *msg)
{
    perror(msg);
    exit(0);
}


void send_command(char * mycmd){
    int i=0;
    uint8_t addr_block[6];
    int addr_block_cnt = 0;
    uint8_t cmd_block[8];
    int cmd_block_cnt = 0;


    //char mycmd[] = "0, 5, 00:00:0A:57:99:30 , 5 , 4";
    //char mycmd[] = "2 5 5000 0002 5 2";
    int myargc;
    char *cmd_args[10];

    tokenize(mycmd, &myargc, " -,", 10, cmd_args);


    uint16_t addr_mode = strtol(cmd_args[0],NULL,10);


    char *p_addr_mode   = cmd_args[0];
    char *p_cmd_mode    = cmd_args[1];
    char *p_addr1 = cmd_args[2];

    char *p_addr2 = NULL;
    char *p_data_to_write        = NULL;
    char *p_offset_addr          = NULL;
    char *p_data_len_to_read     = NULL;

    if(addr_mode == 2){
        p_addr2 = cmd_args[3];
        p_data_to_write       = cmd_args[5];
        p_offset_addr          = cmd_args[4];
        p_data_len_to_read    = cmd_args[5];
    }
    else{

        p_data_to_write       = cmd_args[4];
        p_offset_addr          = cmd_args[3];
        p_data_len_to_read    = cmd_args[4];
    }
/*
    printf("p_addr_mode = %s\n",p_addr_mode );
    printf("p_cmd_mode = %s\n",p_cmd_mode );
    printf("p_addr1 = %s\n",p_addr1 );
    printf("p_addr2 = %s\n",p_addr2 );

    printf("p_offset_addr = %s\n",p_offset_addr);
    printf("p_data_len_to_read = %s\n",p_data_len_to_read );
    printf("p_data_to_write = %s\n",p_data_to_write );
    printf("\n");
*/
    int var0,var1,var2;
    uint8_t cmd_block_val;

    var0 = set_cmd_block(p_addr_mode, p_cmd_mode, &cmd_block_val);
    var1 = create_addressing_block(p_addr_mode, p_addr1, p_addr2, addr_block);
    var2 = create_command_block(p_cmd_mode, p_offset_addr, p_data_len_to_read, p_data_to_write, cmd_block);

    uint8_t COMMAND_TO_SEND[64];
    uint8_t *COMMAND_TO_SEND_PTR = COMMAND_TO_SEND;


/////TEST EXTRA BYTE
    //*COMMAND_TO_SEND_PTR++ = 0x01;
    //*COMMAND_TO_SEND_PTR++ = 0x23;


    *(COMMAND_TO_SEND_PTR++) = STX;
    *(COMMAND_TO_SEND_PTR++) = cmd_block_val;
    if(cmd_block_val == STX){
        *(COMMAND_TO_SEND_PTR++) = '\0';
    }

    for(i=0;i<var1;i++){
        *(COMMAND_TO_SEND_PTR++) = addr_block[i];
        if(addr_block[i] == STX){
            *(COMMAND_TO_SEND_PTR++) = '\0';
        }
    }

    for(i=0;i<var2;i++){
        *(COMMAND_TO_SEND_PTR++) = cmd_block[i];
        if(cmd_block[i] == STX){
        *(COMMAND_TO_SEND_PTR++) = '\0';
        }
    }

    uint8_t CRC_value[2] = {0xFF,0xFF};
    ProtocolBufferGetCrc(&COMMAND_TO_SEND[1],var0+var1+var2,&CRC_value[0],&CRC_value[1]);
    *(COMMAND_TO_SEND_PTR++) = CRC_value[0];
    if(CRC_value[0] == STX) {*(COMMAND_TO_SEND_PTR++) = '\0';}
    *(COMMAND_TO_SEND_PTR++) = CRC_value[1];
    if(CRC_value[1] == STX) {*(COMMAND_TO_SEND_PTR++) = '\0';}


    *(COMMAND_TO_SEND_PTR++) = STX;
    *(COMMAND_TO_SEND_PTR++) = CR;


    int CMD_LEN = COMMAND_TO_SEND_PTR - COMMAND_TO_SEND;
    printf("Sent Message (length = %d)\n",CMD_LEN);



    for(i=0;i<CMD_LEN;i++){
        printf("%x ", COMMAND_TO_SEND[i]);
    }

    printf("\n\n");

    n = write(sockfd,COMMAND_TO_SEND,CMD_LEN);//change strlen with detect termination
    if (n < 0)
         error("ERROR writing to socket");

    //bzero(buffer,256);



}

int receive_command(char * rec_data){
    int i;
    n = read(sockfd,rec_data,255);
    if (n < 0)
         error("ERROR reading from socket");
    printf("Received Message (lenght = %d)\n",n);
    for(i=0;i<n;i++){
        printf("%02x ",hexchar(rec_data[i]));
    }
    printf("\n\n");



    uint8_t CRC_value[2] = {0xFF,0xFF};
    ProtocolBufferGetCrc(&rec_data[1],n-4,&CRC_value[0],&CRC_value[1]);

    //printf("\nthe CRC value is %x %x\n\n", CRC_value[0],CRC_value[1]);
    if(!rec_data[2]){
        printf("ERROR : NONE (GOOD)\n");
    }
    else{
        printf("ERROR : %d\n", rec_data[2]);
    }

    if(ProtocolBufferCheckCrc(&rec_data[1],n-5)){
        printf("CRC MATCHED (GOOD)\n");
    }
    else{
        printf("CRC ERROR!!!\n");
    }

    return n;

}

int init_socket(char * host, char * port){
    char buffer[256];

    portno = atoi(port);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        error("ERROR opening socket");
        exit(0);
    }

    server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
        error("ERROR connecting");
        exit(0);
    }
    else {
        printf("CONNECTED to %s:%d\n\n",host,portno);
    }

}


int main(int argc, char *argv[]){

    int i;
    if (argc < 3) {
       fprintf(stderr,"use the following format to open\n\n %s [hostname] [port]\n\n", argv[0]);
       exit(0);
    }
    init_socket(argv[1],argv[2]);


    //AN EXAMPLATO READ 32BIT BY PHYSICAL ADDRESS, THE OFFSET ADDRESS 0x20 (31) and length = 1)
    //char mycmd[64] = "0, 5, 00:00:0A:57:99:30 , 32 , 1";
    char mycmd[64] = "0, 6, 00:00:0A:57:99:30 , 32 , 4626 ";
    char buffer[256];


    send_command(mycmd);
    receive_command(buffer);

    close(sockfd);


    return 0;
}

