
rule Ransom_Win32_FileCoder_ZC_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 00 4f 00 42 00 69 00 74 00 55 00 6e 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 44 00 65 00 76 00 69 00 63 00 65 00 } //1 IOBitUnlockerDevice
		$a_01_1 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //1 .locked
		$a_01_2 = {5c 00 5f 00 5f 00 5f 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 59 00 6f 00 75 00 72 00 46 00 69 00 6c 00 65 00 73 00 5f 00 5f 00 5f 00 2e 00 74 00 78 00 74 00 } //1 \___RestoreYourFiles___.txt
		$a_01_3 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 73 74 6f 6c 65 6e 21 } //1 All your important files have been encrypted and stolen!
		$a_01_4 = {49 66 20 79 6f 75 20 64 6f 6e 27 74 20 63 6f 6e 74 61 63 74 20 77 69 74 68 69 6e 20 74 68 72 65 65 20 64 61 79 73 2c 20 77 65 27 6c 6c 20 73 74 61 72 74 20 6c 65 61 6b 69 6e 67 20 64 61 74 61 } //1 If you don't contact within three days, we'll start leaking data
		$a_01_5 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 68 61 6e 64 6c 65 20 74 6f 20 64 72 69 76 65 72 } //1 Failed to open handle to driver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}