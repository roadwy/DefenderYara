
rule Trojan_Win32_Amadey_HH_MTB{
	meta:
		description = "Trojan:Win32/Amadey.HH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e1 04 03 cf 03 d0 33 ca 89 4c 24 14 } //01 00 
		$a_01_1 = {31 74 24 14 8b 44 24 28 31 44 24 14 8b 44 24 14 29 44 24 20 } //00 00 
	condition:
		any of ($a_*)
 
}