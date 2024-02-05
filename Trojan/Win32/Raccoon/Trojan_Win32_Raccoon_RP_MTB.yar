
rule Trojan_Win32_Raccoon_RP_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 45 fc 8b 45 0c 33 45 fc 89 45 fc 8b 45 08 8b 4d fc 89 08 c9 c2 0c 00 90 02 30 55 8b ec 8b 45 0c 8b 4d 08 c1 e0 04 89 01 5d c2 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}