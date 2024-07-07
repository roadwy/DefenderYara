
rule TrojanSpy_AndroidOS_Hermit_B{
	meta:
		description = "TrojanSpy:AndroidOS/Hermit.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {76 6f 69 64 61 32 64 66 61 65 34 35 38 31 66 35 } //1 voida2dfae4581f5
		$a_01_1 = {53 43 52 45 45 4e 5f 4f 4e 5f 52 45 51 55 45 53 54 45 44 } //1 SCREEN_ON_REQUESTED
		$a_00_2 = {77 61 74 63 68 64 6f 67 55 6e 69 6e 73 74 61 6c 6c 54 73 } //1 watchdogUninstallTs
		$a_01_3 = {45 58 50 4c 4f 49 54 5f 53 55 43 43 45 44 45 44 } //1 EXPLOIT_SUCCEDED
		$a_01_4 = {50 4c 41 54 46 4f 52 4d 5f 4c 49 4d 49 54 5f 52 45 41 43 48 45 44 } //1 PLATFORM_LIMIT_REACHED
		$a_01_5 = {50 45 52 4d 49 53 53 49 4f 4e 5f 49 4e 46 4f 5f 44 45 4e 49 45 44 } //1 PERMISSION_INFO_DENIED
		$a_01_6 = {52 45 43 4f 52 44 45 52 5f 45 56 45 4e 54 5f 45 52 52 4f 52 } //1 RECORDER_EVENT_ERROR
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}