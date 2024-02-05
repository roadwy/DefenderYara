
rule Trojan_Win32_Carrobat_C{
	meta:
		description = "Trojan:Win32/Carrobat.C,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 63 20 64 65 6c 20 2f 66 20 2f 71 } //01 00 
		$a_01_1 = {72 65 6e 20 31 2e 74 78 74 20 31 2e 62 61 74 } //01 00 
		$a_01_2 = {26 26 20 31 2e 62 61 74 20 26 26 20 65 78 69 74 } //01 00 
		$a_01_3 = {43 3a 20 26 26 20 63 64 20 25 54 45 4d 50 25 } //00 00 
	condition:
		any of ($a_*)
 
}