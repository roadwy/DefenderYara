
rule Backdoor_Win32_CobaltStrikeLoader_CM_dha{
	meta:
		description = "Backdoor:Win32/CobaltStrikeLoader.CM!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 5c 00 [0-28] 5c 00 61 00 63 00 72 00 6f 00 62 00 61 00 74 00 2e 00 65 00 78 00 65 00 } //1
		$a_02_1 = {2f 43 20 72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 [0-0f] 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 53 48 45 4c 4c 33 32 2e 44 4c 4c 2c 53 68 65 6c 6c 45 78 65 63 5f } //1
		$a_00_2 = {2a 28 70 20 2b 20 25 64 29 20 3a 20 25 66 } //1 *(p + %d) : %f
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_CobaltStrikeLoader_CM_dha_2{
	meta:
		description = "Backdoor:Win32/CobaltStrikeLoader.CM!dha,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //5 rundll32.exe
		$a_00_1 = {31 00 31 00 39 00 38 00 35 00 } //5 11985
		$a_00_2 = {43 00 6c 00 65 00 61 00 72 00 4d 00 79 00 54 00 72 00 61 00 63 00 6b 00 73 00 42 00 79 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 ClearMyTracksByProcess
		$a_00_3 = {41 00 6c 00 6c 00 6f 00 63 00 43 00 6f 00 6e 00 73 00 6f 00 6c 00 65 00 } //1 AllocConsole
		$a_00_4 = {69 00 6e 00 65 00 74 00 63 00 70 00 6c 00 2e 00 63 00 70 00 6c 00 } //-100 inetcpl.cpl
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*-100) >=11
 
}