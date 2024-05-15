
rule Trojan_Win32_Bayrob_ARA_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 10 30 11 41 40 3b cf 75 f6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Bayrob_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Bayrob.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {80 39 00 74 90 01 01 80 31 1a 41 eb f5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}