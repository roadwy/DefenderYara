
rule Trojan_Win32_Bunitu_DSK_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b d2 8b ca 8b d2 ff 35 90 01 04 8b d2 8f 45 fc 8b d2 31 4d fc 8b d2 8b 45 fc 8b d2 8b c8 8b d2 b8 00 00 00 00 03 c1 89 45 fc a1 90 01 04 8b 4d fc 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Bunitu_DSK_MTB_2{
	meta:
		description = "Trojan:Win32/Bunitu.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {a1 38 1b 55 00 8b c0 8b ca 8b c0 a3 54 1b 55 00 8b c0 8b 3d 54 1b 55 00 33 f9 89 3d 54 1b 55 00 8b c0 a1 54 1b 55 00 c7 05 38 1b 55 00 00 00 00 00 01 05 38 1b 55 00 8b 0d 48 1b 55 00 8b 15 38 1b 55 00 89 11 } //00 00 
	condition:
		any of ($a_*)
 
}