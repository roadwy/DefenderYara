
rule Trojan_Win32_Parallax_PB_MTB{
	meta:
		description = "Trojan:Win32/Parallax.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 8b 55 f8 8b 0c 90 90 8b 5d 14 8b 45 fc 33 0c 83 8b 55 08 8b 45 f8 89 0c 82 8b 15 90 01 04 3b 15 90 01 04 8b 4d 90 01 01 49 3b 4d fc 75 07 33 c0 89 45 fc eb 2c 0f be 15 90 01 04 3b 15 90 01 04 7f 0a c7 05 90 01 05 00 00 00 80 3d 90 01 04 00 74 07 80 3d 90 01 04 00 ff 45 fc ff 45 f8 8b 4d f8 3b 4d 10 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}