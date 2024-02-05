
rule Trojan_Win32_Ursnif_SMKA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SMKA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b c0 5f 8b 4d e8 2b c8 0f b7 05 e0 3f 44 00 2b c1 66 a3 e0 3f 44 00 8b 45 0c 2d d2 12 00 00 0f b7 0d e0 3f 44 00 2b c1 0f b6 0d de 3f 44 00 03 c1 0f b6 0d de 3f 44 00 03 c8 88 0d de 3f 44 00 } //01 00 
		$a_01_1 = {83 e8 07 2b 45 0c a2 de 3f 44 00 a1 0c 40 44 00 6b c0 5f 8b 4d e8 2b c8 0f b7 05 e0 3f 44 00 2b c1 66 a3 e0 3f 44 00 } //00 00 
	condition:
		any of ($a_*)
 
}