
rule Trojan_Win32_Raccoon_EA_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 04 00 00 00 8b 45 0c 83 6d fc 02 90 01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}