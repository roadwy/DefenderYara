
rule Trojan_BAT_Tnega_AL_MTB{
	meta:
		description = "Trojan:BAT/Tnega.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {54 4f 4b 45 4e 5f 53 54 45 41 4c 45 52 5f 43 52 45 41 54 4f 52 2e 50 72 6f 70 65 72 74 69 65 73 } //1 TOKEN_STEALER_CREATOR.Properties
		$a_81_1 = {24 33 34 30 62 65 63 66 61 2d 31 36 38 38 2d 34 63 33 32 2d 61 61 34 39 2d 33 30 66 64 62 34 30 30 35 65 34 62 } //1 $340becfa-1688-4c32-aa49-30fdb4005e4b
		$a_81_2 = {49 74 72 6f 75 62 6c 76 65 54 53 43 5c 62 69 6e 5f 63 6f 70 79 5c 6f 62 6a 5c 44 65 62 75 67 } //1 ItroublveTSC\bin_copy\obj\Debug
		$a_01_3 = {43 00 3a 00 2f 00 74 00 65 00 6d 00 70 00 2f 00 66 00 69 00 6e 00 61 00 6c 00 72 00 65 00 73 00 2e 00 62 00 61 00 74 00 } //1 C:/temp/finalres.bat
		$a_01_4 = {43 00 3a 00 2f 00 74 00 65 00 6d 00 70 00 2f 00 66 00 69 00 6e 00 61 00 6c 00 72 00 65 00 73 00 32 00 2e 00 76 00 62 00 73 00 } //1 C:/temp/finalres2.vbs
		$a_01_5 = {43 00 3a 00 2f 00 74 00 65 00 6d 00 70 00 2f 00 57 00 65 00 62 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 50 00 61 00 73 00 73 00 56 00 69 00 65 00 77 00 2e 00 65 00 78 00 65 00 } //1 C:/temp/WebBrowserPassView.exe
		$a_01_6 = {43 00 3a 00 2f 00 74 00 65 00 6d 00 70 00 2f 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 } //1 C:/temp/curl.exe
		$a_01_7 = {43 00 3a 00 2f 00 74 00 65 00 6d 00 70 00 2f 00 66 00 69 00 6c 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 C:/temp/filed.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}