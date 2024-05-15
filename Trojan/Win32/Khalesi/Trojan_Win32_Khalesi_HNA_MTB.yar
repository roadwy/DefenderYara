
rule Trojan_Win32_Khalesi_HNA_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 01 ea 31 01 81 c1 04 00 00 00 29 f2 } //01 00 
		$a_01_1 = {8b 0c 24 83 c4 04 } //00 00 
	condition:
		any of ($a_*)
 
}