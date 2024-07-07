
rule TrojanSpy_BAT_Banker_D{
	meta:
		description = "TrojanSpy:BAT/Banker.D,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 00 65 00 20 00 61 00 72 00 65 00 20 00 73 00 6f 00 72 00 72 00 79 00 20 00 62 00 75 00 74 00 20 00 77 00 65 00 20 00 63 00 61 00 6e 00 6e 00 6f 00 74 00 20 00 63 00 6f 00 6e 00 74 00 69 00 6e 00 75 00 65 00 20 00 77 00 69 00 74 00 68 00 20 00 79 00 6f 00 75 00 72 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 62 00 65 00 63 00 61 00 75 00 73 00 65 00 20 00 79 00 6f 00 75 00 20 00 68 00 61 00 76 00 65 00 20 00 65 00 6e 00 74 00 65 00 72 00 65 00 64 00 20 00 6f 00 6e 00 65 00 20 00 6f 00 72 00 20 00 6d 00 6f 00 72 00 65 00 20 00 64 00 65 00 74 00 61 00 69 00 6c 00 73 00 20 00 69 00 6e 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 6c 00 79 00 2e 00 } //2 We are sorry but we cannot continue with your request because you have entered one or more details incorrectly.
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 57 6f 72 64 2e 66 6f 72 6d 43 61 70 69 74 61 6c 6f 6e 65 2e 72 65 73 6f 75 72 63 65 73 } //5 MicrosoftWord.formCapitalone.resources
		$a_01_2 = {46 6f 72 6d 4c 4c 4f 59 44 53 5f 4c 6f 61 64 } //2 FormLLOYDS_Load
		$a_01_3 = {73 65 74 5f 66 6f 72 6d 42 61 72 63 6c 61 79 73 } //3 set_formBarclays
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3) >=12
 
}