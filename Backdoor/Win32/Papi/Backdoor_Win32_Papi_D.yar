
rule Backdoor_Win32_Papi_D{
	meta:
		description = "Backdoor:Win32/Papi.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 41 50 41 50 49 33 32 [0-05] 43 72 65 61 74 65 53 65 72 76 69 63 65 20 66 61 69 6c [0-05] 4f 70 65 6e 53 65 72 76 69 63 65 20 66 61 69 6c } //1
		$a_03_1 = {8a 17 80 ea 41 8a 4f 01 80 e9 41 c1 e1 04 02 d1 88 10 80 ea ?? 80 f2 ?? 80 c2 ?? 88 10 40 83 c7 02 4e 75 dc } //1
		$a_01_2 = {80 38 2a 74 22 46 40 4a 75 f6 eb 1b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}