
rule Trojan_Win32_Oficla_P{
	meta:
		description = "Trojan:Win32/Oficla.P,SIGNATURE_TYPE_PEHSTR,05 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {2f 62 62 2e 70 68 70 3f 76 3d } //01 00 
		$a_01_1 = {74 61 73 6b 69 64 3a } //01 00 
		$a_01_2 = {72 75 6e 75 72 6c 3a } //01 00 
		$a_01_3 = {69 6e 65 74 6d 69 62 31 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}