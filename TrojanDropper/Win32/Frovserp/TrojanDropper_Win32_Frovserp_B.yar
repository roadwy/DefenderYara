
rule TrojanDropper_Win32_Frovserp_B{
	meta:
		description = "TrojanDropper:Win32/Frovserp.B,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 67 00 69 00 75 00 2e 00 73 00 79 00 73 00 } //10 \drivers\giu.sys
		$a_01_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 6d 00 65 00 2e 00 62 00 61 00 74 00 } //10 deleteme.bat
		$a_01_2 = {54 00 65 00 78 00 74 00 4c 00 6f 00 67 00 2e 00 64 00 61 00 74 00 } //1 TextLog.dat
		$a_01_3 = {4d 00 79 00 5f 00 44 00 72 00 69 00 76 00 65 00 72 00 4c 00 69 00 6e 00 6b 00 4e 00 61 00 6d 00 65 00 5f 00 74 00 65 00 73 00 74 00 } //1 My_DriverLinkName_test
		$a_01_4 = {50 00 4d 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 PMLauncher.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}