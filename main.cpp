//
//  main.cpp
//  CactusPacker
//
//  Created by Suu on 12/06/2015.
//  Copyright (c) 2015 suu. All rights reserved.
//

#include <iostream>
#include <string>
#include <unistd.h>

#include "MachoFile.h"

using namespace std;

int system(const char * command);

int main(int argc, const char *argv[])
{
    if (argc < 2)
    {
        cout << "Invalid argument. Usage: cactus [file path]" << endl;
        return -1;
    }
    
    string path(argv[1]);
    MachoFile *originalFile = new MachoFile(path);
    
    cout << originalFile->filePath << endl;
    
    //Encryption
    SubLCBrick *encryptBrick = (SubLCBrick *)originalFile->getBrickWithName("__text");
    if (!encryptBrick)
    {
        cout << "No Such Brick" << endl;
        return -1;
    }
    DataBrick *encryptDataBrick = encryptBrick->myData;
    
    //originalFile->displayBrickInformation(encryptDataBrick);
    
    cout << "Encryption file" << endl;
    char *replacedData = new char[encryptDataBrick->size];
    for (int i = 0; i < encryptDataBrick->size; i++)
    {
        replacedData[i] = encryptDataBrick->rawData[i] ^ 0xBC;
    }
    
    if (originalFile->replaceBrickDataWithBrickAndDataAndLength(encryptDataBrick, replacedData, encryptDataBrick->size))
    {
        cout << "Encrypted Data cannot be placed" << endl;
    }
    delete(replacedData);
    
    //Assign write privilege
    cout << "Assigning write privilege to __TEXT segment" << endl;
    LCBrick *TEXTSegement = (LCBrick *)originalFile->getBrickWithName("__TEXT");
    TEXTSegement->makeWritable();
    
    //Build decode function
    cout << "Constructing decode function";
    SubLCBrick *decodeBrick = (SubLCBrick *)originalFile->getBrickWithName("__unwind_info");
    if (!decodeBrick)
    {
        cout << endl <<"No Such Brick" << endl;
        return -1;
    }
    DataBrick *decodeDataBrick = decodeBrick->myData;
    char *decodeFunction = new char[decodeDataBrick->size];
    
    for (int i = 0; i < decodeDataBrick->size; i++)
    {
        decodeFunction[i] = 0;
    }
    
    //Segment1 size: 5
    const char *segment1 =  "\x50"                      //push rax
                            "\x48\x31\xc0"              //xor rax, rax
                            "\xbb";                     //mov ebx, XXXX
    memcpy(decodeFunction, segment1, 5*sizeof(char));
    cout << ".";
    
    //Segment2 size: 4
    char *segment2 = new char[4];
    originalFile->reverseBit(segment2, encryptDataBrick->size, 4);
    memcpy(&decodeFunction[5], segment2, 4*sizeof(char));
    delete segment2;
    cout << ".";
    
    //Segment3 size: 10
    const char *segment3 =  "\xe8\x00\x00\x00\x00"      //call next
                            "\x41\x58"                  //pop r8
                            "\x49\x81\xe8";             //sub r8, XXXX
    memcpy(&decodeFunction[9], segment3, 10*sizeof(char));
    cout << ".";
    
    //Segment4 size: 4
    char *segment4 = new char[4];
    //Current offset to "__text" offset = Decode offset - Encrypt offset + everything befor call(including call)
    originalFile->reverseBit(segment4, decodeDataBrick->dataOffset - encryptDataBrick->dataOffset + 14 , 4);
    memcpy(&decodeFunction[19], segment4, 4*sizeof(char));
    delete segment4;
    cout << ".";
    
    //Segment5 size: 34
    const char *segment5 =  "\x41\x50"                  //push r8
                            "\x66\x41\x8b\x00"          //mov ax, [r8]  ;decodeStart
                            "\x66\x35\xbc\x00"          //xor ax, 0xbc
                            "\x66\x41\x89\x00"          //mov word [r8], ax
                            "\x49\x83\xc0\x01"          //add r8, 0x1
                            "\x66\x83\xeb\x01"          //sub bx, 0x1
                            "\x66\x83\xfb\x00"          //cmp bx, 0x0
                            "\x75\xe6"                  //jne decodeStart
                            "\x41\x58"                  //pop r8
                            "\x58"                      //pop rax
                            "\x41\xff\xe0";             //jmp r8
    memcpy(&decodeFunction[23], segment5, 34*sizeof(char));
    cout << "." << endl;
    
    //Inject Decode function
    cout << "Injection decode function" << endl;
    if (originalFile->replaceBrickDataWithBrickAndDataAndLength(decodeDataBrick, decodeFunction, decodeDataBrick->size))
    {
        cout << "Error" << endl;
    }
    
    //Modify EntryPoint
    cout << "Modifying entrypoint" << endl;
    LCBrick *entry = (LCBrick *)originalFile->getBrickWithType(LC_MAIN);
    if (!entry)
    {
        #ifdef DEBUG
        DEBUG_COUT << "UNIXTHREAD" << endl;
        #endif
        entry = (LCBrick *)originalFile->getBrickWithType(LC_UNIXTHREAD);
    }
    entry->setEntryPoint(decodeDataBrick->getOffset());
    
    //Clear __objc_methname
    /*
    cout << "Emptying __objc_methname" << endl;
    SubLCBrick *methname = (SubLCBrick *)originalFile->getBrickWithName("__objc_methname");
    originalFile->clearBrickData(methname->myData);
    SubLCBrick *classname = (SubLCBrick *)originalFile->getBrickWithName("__objc_classname");
    originalFile->clearBrickData(classname->myData);
    SubLCBrick *methtype = (SubLCBrick *)originalFile->getBrickWithName("__objc_methtype");
    originalFile->clearBrickData(methtype->myData);
    */
    //////////
    // Test //
    //////////
    /*
    Brick *myBrick = originalFile->getBrickWithName("__TEXT");
    originalFile->displayBrickInformation(myBrick);
    myBrick = originalFile->getBrickWithName("Magic");
    originalFile->displayBrickInformation(myBrick);
    myBrick = originalFile->getBrickWithName("__text");
    originalFile->displayBrickInformation(myBrick);
    
    DataBrick *myDataBrick = ((SubLCBrick *)myBrick)->myData;
    char *replacedData = new char[myDataBrick->size];
    for (int i = 0; i < myDataBrick->size; i++)
    {
        replacedData[i] = 0x11;
    }
    
    if (originalFile->replaceBrickDataWithBrickAndDataAndLength(myDataBrick, replacedData, myDataBrick->size))
    {
        cout << "Error" << endl;
    }
    
    myBrick = originalFile->getBrickWithName("__DATA");
    ((LCBrick *)myBrick)->makeExecutable();
    ((LCBrick *)myBrick)->removeVMProtectionFlag(VM_PROT_WRITE);
     */
    
    //Save
    cout << "Saving" << endl;
    string newPath = path+"_hacked";
    originalFile->saveAs(newPath);
    
    //chmod
    cout << "Assign execute privilege" << endl;
    string command = "chmod +x "+newPath;
    system(command.c_str());
    
    cout << "Done" << endl;
    //Free
    delete(originalFile);
    
    return 0;
}
