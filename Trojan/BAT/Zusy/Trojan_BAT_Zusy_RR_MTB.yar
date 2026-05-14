
rule Trojan_BAT_Zusy_RR_MTB{
	meta:
		description = "Trojan:BAT/Zusy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 2c 07 03 8e 69 1f 40 2f 06 28 [0-05] 2a 03 1f 3c 28 [0-05] 0a 06 16 32 06 } //1
		$a_01_1 = {50 65 72 66 6f 72 6d 49 6e 6a 65 63 74 69 6f 6e } //1 PerformInjection
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}