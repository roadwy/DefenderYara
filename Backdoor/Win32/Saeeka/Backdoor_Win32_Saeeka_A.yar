
rule Backdoor_Win32_Saeeka_A{
	meta:
		description = "Backdoor:Win32/Saeeka.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 33 65 4b 61 20 52 41 54 20 41 74 74 61 63 6b 65 72 20 20 20 20 20 20 20 20 6c 6c 6c 20 42 79 20 48 41 43 4b 45 52 38 35 20 6c 6c 6c } //01 00 
		$a_01_1 = {52 65 6d 6f 74 65 20 44 6f 77 6e 6c 6f 61 64 2f 45 78 65 63 75 74 65 } //01 00 
		$a_01_2 = {28 68 61 63 6b 65 72 38 35 2e 6e 6f 2d 69 70 2e 62 69 7a 29 } //00 00 
	condition:
		any of ($a_*)
 
}