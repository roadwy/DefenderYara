
rule Trojan_Win32_Fauppod_C_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 83 c4 04 90 00 } //02 00 
		$a_01_1 = {80 3a 00 74 } //02 00 
		$a_01_2 = {57 64 72 63 74 66 50 6a 6e 6b 68 62 67 } //02 00 
		$a_01_3 = {4d 62 69 68 75 79 76 74 79 44 74 72 63 79 76 } //02 00 
		$a_01_4 = {52 63 79 74 76 67 48 76 75 62 68 6d } //00 00 
	condition:
		any of ($a_*)
 
}