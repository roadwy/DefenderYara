
rule Backdoor_Win32_Saeeka_B{
	meta:
		description = "Backdoor:Win32/Saeeka.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 33 65 6b 61 20 54 6f 6f 6c 7a } //01 00 
		$a_01_1 = {5c 00 73 00 33 00 6b 00 61 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_2 = {5c 00 48 00 61 00 63 00 6b 00 65 00 64 00 2e 00 62 00 6d 00 70 00 } //01 00 
		$a_01_3 = {4f 00 50 00 45 00 4e 00 56 00 49 00 52 00 55 00 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}