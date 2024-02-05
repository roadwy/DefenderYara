
rule Trojan_Win32_Masson_C{
	meta:
		description = "Trojan:Win32/Masson.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 65 74 6c 4d 65 46 57 53 72 65 76 69 63 65 } //01 00 
		$a_01_1 = {49 6e 65 74 6c 20 49 6e 63 2e } //01 00 
		$a_01_2 = {62 30 35 61 63 33 33 62 2d 33 61 34 38 2d 34 38 39 64 2d 61 32 39 63 2d 36 64 66 66 35 34 38 37 33 62 36 33 } //00 00 
		$a_01_3 = {00 5d } //04 00 
	condition:
		any of ($a_*)
 
}