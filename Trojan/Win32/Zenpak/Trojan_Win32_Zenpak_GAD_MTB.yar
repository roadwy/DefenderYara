
rule Trojan_Win32_Zenpak_GAD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff d1 83 ec 90 01 01 8b 4c 24 90 01 01 81 c1 90 01 04 81 f9 90 01 04 89 44 24 90 01 01 89 4c 24 90 00 } //0a 00 
		$a_01_1 = {31 20 83 f0 05 48 e8 } //00 00 
	condition:
		any of ($a_*)
 
}