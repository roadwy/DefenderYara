
rule Trojan_Win32_Azorult_NK_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0f 88 04 0e 81 fa 90 02 04 75 06 89 2d 90 02 04 41 3b ca 72 e7 90 00 } //1
		$a_81_1 = {53 63 72 6f 6c 6c 43 6f 6e 73 6f 6c 65 53 63 72 65 65 6e 42 75 66 66 65 72 57 } //1 ScrollConsoleScreenBufferW
		$a_81_2 = {47 65 74 43 6f 6d 6d 4d 61 73 6b } //1 GetCommMask
		$a_81_3 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //1 SystemFunction036
		$a_81_4 = {47 41 49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 GAIsProcessorFeaturePresent
		$a_81_5 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //1 SizeofResource
		$a_81_6 = {45 52 52 4f 52 44 49 41 4c 4f 47 } //1 ERRORDIALOG
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}