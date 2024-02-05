
rule Trojan_Win32_Raccoon_R_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 } //00 00 
	condition:
		any of ($a_*)
 
}