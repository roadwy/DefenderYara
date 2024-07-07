
rule Backdoor_BAT_Bladabindi_PA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 79 70 65 53 63 72 69 70 74 20 4b 65 79 62 6f 61 72 64 20 53 79 6e 63 2e 65 78 65 } //1 TypeScript Keyboard Sync.exe
		$a_01_1 = {4f 00 4e 00 49 00 4f 00 5a 00 4c 00 5a 00 4c 00 57 00 4e 00 4a 00 54 00 50 00 55 00 50 00 4c 00 59 00 4d 00 42 00 46 00 43 00 47 00 42 00 51 00 46 00 49 00 51 00 44 00 5a 00 56 00 44 00 47 00 4e 00 } //1 ONIOZLZLWNJTPUPLYMBFCGBQFIQDZVDGN
		$a_01_2 = {67 65 74 5f 44 47 47 48 44 30 34 41 56 32 45 4e 55 32 4b 36 56 42 30 } //1 get_DGGHD04AV2ENU2K6VB0
		$a_01_3 = {67 65 74 5f 41 4f 4f 52 53 52 44 59 4f 33 4f 51 50 4e 48 44 38 33 } //1 get_AOORSRDYO3OQPNHD83
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}