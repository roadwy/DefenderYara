
rule Trojan_Win32_Ursnif_VR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.VR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 6c 24 10 8b c8 2b ca 81 c6 20 ef 8f 01 83 c1 04 89 b4 2b 7e ea ff ff 81 3d 90 01 04 d1 24 00 00 8d 84 08 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8b 6c 24 10 a1 90 01 04 8d 84 28 90 01 04 89 44 24 14 8b 00 bd c3 f4 d8 11 8d 9c 37 90 01 04 a3 90 01 04 89 1d 90 01 04 8d 84 0f 90 01 04 3b d5 75 90 00 } //01 00 
		$a_02_2 = {8b 54 24 10 2d 9f 5c 00 00 a3 90 01 04 a1 90 01 04 8d 84 10 90 01 04 89 44 24 14 8b 00 a3 90 01 04 a1 90 01 04 8d 7c 31 09 0f af c7 2b c1 a3 90 01 04 81 fe 9f 8d ab 2f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}