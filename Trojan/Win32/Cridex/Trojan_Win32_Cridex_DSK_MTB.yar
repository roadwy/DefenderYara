
rule Trojan_Win32_Cridex_DSK_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {05 ec 9f f5 01 89 84 1a 90 01 02 ff ff 83 c3 04 8b d6 89 3d 90 01 04 8d 6c 2a 0f 89 5c 24 10 90 09 06 00 8b 15 90 00 } //02 00 
		$a_02_1 = {0f b6 cb 03 c1 8b 4d fc 25 ff 00 00 00 8a 80 90 01 04 5e 33 cd 5b 90 09 07 00 0f b6 80 90 00 } //02 00 
		$a_00_2 = {8b 44 24 20 8a 4c 14 24 30 08 40 ff 4c 24 1c 89 44 24 20 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}