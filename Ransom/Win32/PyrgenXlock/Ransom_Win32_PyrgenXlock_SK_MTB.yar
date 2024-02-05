
rule Ransom_Win32_PyrgenXlock_SK_MTB{
	meta:
		description = "Ransom:Win32/PyrgenXlock.SK!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 49 6e 63 6c 75 64 65 5c 70 79 63 6f 6e 66 69 67 2e 68 } //02 00 
		$a_01_1 = {78 62 69 74 63 6f 69 6e 2e 62 6d 70 } //02 00 
		$a_01_2 = {78 6c 6f 63 6b 2e 62 6d 70 } //02 00 
		$a_01_3 = {78 6c 6f 63 6b 2e 69 63 6f } //01 00 
		$a_01_4 = {78 72 75 6e 74 69 6d 65 2e 63 66 67 } //01 00 
		$a_01_5 = {7a 6f 75 74 30 30 2d 50 59 5a 2e 70 79 7a } //00 00 
	condition:
		any of ($a_*)
 
}