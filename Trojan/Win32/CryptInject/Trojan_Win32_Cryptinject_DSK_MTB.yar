
rule Trojan_Win32_Cryptinject_DSK_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 10 73 90 01 01 8b 4d f8 8b 55 f4 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 8b 55 f4 83 c2 01 89 55 f4 eb 90 00 } //01 00 
		$a_00_1 = {48 66 73 64 66 67 6b 6a 35 33 } //01 00 
		$a_00_2 = {48 66 73 64 66 4a 67 34 32 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cryptinject_DSK_MTB_2{
	meta:
		description = "Trojan:Win32/Cryptinject.DSK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 85 d4 ef ff ff 8b 9d d0 ef ff ff c0 e0 06 08 85 d5 ef ff ff 8a 85 d6 ef ff ff 88 04 1f 81 3d bc ff 16 04 0e 06 00 00 75 } //02 00 
		$a_01_1 = {a1 34 89 14 04 8a 4c 18 01 88 8d d7 ef ff ff 8a 4c 18 02 8a 44 18 03 8a d8 80 e3 f0 c0 e3 02 81 3d bc ff 16 04 d3 0b 00 00 88 8d d5 ef ff ff 88 85 d4 ef ff ff 75 } //00 00 
	condition:
		any of ($a_*)
 
}