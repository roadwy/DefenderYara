
rule Trojan_Win32_Picsys_SRPP_MTB{
	meta:
		description = "Trojan:Win32/Picsys.SRPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4d f4 03 4d f8 8a 11 88 55 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 4d ff 81 f1 b7 00 00 00 88 4d ff 0f b6 55 ff c1 fa 02 0f b6 45 ff c1 e0 06 0b d0 88 55 ff 0f b6 4d ff f7 d1 88 4d ff 0f b6 55 ff 81 ea b1 00 00 00 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 81 c2 b5 00 00 00 88 55 ff 0f b6 45 ff 35 e0 00 00 00 88 45 ff 0f b6 4d ff f7 d1 88 4d ff 0f b6 55 ff 81 f2 b0 00 00 00 88 55 ff 0f b6 45 ff 03 45 f8 88 } //0a 00 
		$a_01_1 = {45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff 83 ea 4a 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff 03 4d f8 88 4d ff 0f b6 55 ff 81 f2 f9 00 00 00 88 55 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 4d ff f7 d9 88 4d ff 0f b6 55 ff 2b 55 f8 88 55 ff 0f b6 45 ff d1 f8 0f b6 4d ff c1 e1 07 0b c1 88 45 ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 4d ff c1 f9 05 0f b6 55 ff c1 e2 03 0b ca 88 4d ff 0f b6 45 ff 2b 45 f8 88 45 ff 8b 4d f4 03 4d f8 8a 55 ff 88 11 e9 b1 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}