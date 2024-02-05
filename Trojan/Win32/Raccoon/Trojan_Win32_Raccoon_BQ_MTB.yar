
rule Trojan_Win32_Raccoon_BQ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d } //0a 00 
		$a_02_1 = {31 06 c9 c2 04 00 33 44 24 04 c2 04 00 81 00 90 01 04 c3 01 08 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}