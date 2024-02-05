
rule Trojan_Win32_Zusy_MBHK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 74 76 79 62 75 46 74 76 79 62 } //01 00 
		$a_01_1 = {4b 6e 75 62 79 46 74 76 79 62 } //01 00 
		$a_01_2 = {44 74 72 79 76 62 68 59 63 79 76 67 68 62 6a } //01 00 
		$a_01_3 = {55 72 63 74 76 4b 74 63 76 79 62 } //00 00 
	condition:
		any of ($a_*)
 
}