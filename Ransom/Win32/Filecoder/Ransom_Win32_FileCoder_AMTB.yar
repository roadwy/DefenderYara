
rule Ransom_Win32_FileCoder_AMTB{
	meta:
		description = "Ransom:Win32/FileCoder!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {45 6e 74 65 72 20 63 6f 6e 66 69 72 6d 61 74 69 6f 6e 20 6f 66 20 70 61 79 6d 65 6e 74 } //Enter confirmation of payment  1
		$a_80_1 = {50 61 79 6d 65 6e 74 20 6e 6f 74 20 72 65 63 65 69 76 65 64 } //Payment not received  1
		$a_80_2 = {54 6f 20 6f 70 65 6e 20 50 43 2c 20 70 6c 65 61 73 65 20 73 65 6e 64 20 24 31 30 30 } //To open PC, please send $100  1
		$a_80_3 = {50 43 20 69 73 20 6e 6f 77 20 70 72 6f 63 65 73 73 65 64 21 } //PC is now processed!  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule Ransom_Win32_FileCoder_AMTB_2{
	meta:
		description = "Ransom:Win32/FileCoder!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_80_0 = {2e 6c 69 6d 62 6f } //.limbo  2
		$a_80_1 = {59 6f 75 72 20 41 6c 6c 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 20 57 69 74 68 20 48 69 67 68 20 6c 65 76 65 6c 20 43 72 79 70 74 6f 67 72 61 70 68 79 20 41 6c 67 6f 72 69 74 68 6d } //Your All Files Encrypted With High level Cryptography Algorithm  2
		$a_80_2 = {4e 43 31 75 76 67 47 63 4d 61 4b 4c 79 6a 66 57 54 78 39 48 } //NC1uvgGcMaKLyjfWTx9H  1
		$a_80_3 = {61 73 6d 6f 64 65 75 73 61 73 6d 6f 64 65 75 73 } //asmodeusasmodeus  1
		$a_80_4 = {50 61 79 20 46 6f 72 20 44 65 63 72 79 70 74 69 6f 6e } //Pay For Decryption  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=7
 
}
rule Ransom_Win32_FileCoder_AMTB_3{
	meta:
		description = "Ransom:Win32/FileCoder!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 65 6e 64 20 75 73 20 31 30 30 30 30 30 20 62 69 74 63 6f 69 6e 20 74 6f 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 61 64 64 72 65 73 73 3a } //Send us 100000 bitcoin to the following address:  3
		$a_80_1 = {50 61 79 20 6d 65 20 24 31 30 30 30 20 77 69 74 68 69 6e 20 37 32 20 68 6f 75 72 73 20 6f 72 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 20 66 6f 72 65 76 65 72 2e } //Pay me $1000 within 72 hours or your files will be deleted forever.  2
		$a_80_2 = {43 6f 6e 74 61 63 74 20 6d 65 20 61 74 20 5b 65 6d 61 69 6c 20 61 64 64 72 65 73 73 5d 2e } //Contact me at [email address].  1
		$a_80_3 = {72 61 6e 73 6f 6d 5f 6e 6f 74 65 2e 74 78 74 } //ransom_note.txt  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=6
 
}