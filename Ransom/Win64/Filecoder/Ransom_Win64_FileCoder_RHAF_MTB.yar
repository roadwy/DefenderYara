
rule Ransom_Win64_FileCoder_RHAF_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.RHAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 64 86 0b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 02 2b 00 a2 39 00 00 b8 4f 00 00 1a 00 00 f0 13 } //2
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //3 Your files have been encrypted.
		$a_01_2 = {54 6f 20 64 65 63 72 79 70 74 20 74 68 65 6d 2c 20 79 6f 75 20 6d 75 73 74 20 70 61 79 20 31 20 42 69 74 63 6f 69 6e 20 74 6f 20 74 68 65 20 66 6f 6c 6c 6f 77 69 6e 67 20 61 64 64 72 65 73 73 3a } //2 To decrypt them, you must pay 1 Bitcoin to the following address:
		$a_01_3 = {73 6d 69 6d 65 65 6e 63 72 79 70 74 } //1 smimeencrypt
		$a_01_4 = {65 78 74 65 6e 64 65 64 4b 65 79 55 73 61 67 65 } //1 extendedKeyUsage
		$a_01_5 = {48 61 72 64 77 61 72 65 20 4d 6f 64 75 6c 65 20 4e 61 6d 65 } //1 Hardware Module Name
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}