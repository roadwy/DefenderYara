
rule Trojan_Win32_Raccoon_RPU_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c6 f7 f3 8a 0c 0a 30 0c 3e 46 8b 4d fc 3b 75 0c 72 eb } //00 00 
	condition:
		any of ($a_*)
 
}