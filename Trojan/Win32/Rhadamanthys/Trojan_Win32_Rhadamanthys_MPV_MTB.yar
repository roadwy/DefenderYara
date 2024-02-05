
rule Trojan_Win32_Rhadamanthys_MPV_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.MPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 90 01 01 8d 3c 33 c7 05 90 01 08 c7 05 90 01 08 89 4c 24 18 8b 44 24 28 01 44 24 18 81 3d 90 01 08 75 90 01 01 8d 54 24 38 52 6a 00 ff 15 90 01 04 8b 4c 24 18 8b 44 24 14 33 cf 33 c1 2b e8 8d 44 24 1c e8 70 90 01 04 4c 24 20 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}