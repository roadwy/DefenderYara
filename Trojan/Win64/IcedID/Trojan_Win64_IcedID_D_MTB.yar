
rule Trojan_Win64_IcedID_D_MTB{
	meta:
		description = "Trojan:Win64/IcedID.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 c3 41 81 c3 18 8b e0 c1 41 83 eb 01 41 81 eb 18 8b e0 c1 41 0f af c3 83 e0 01 83 f8 00 0f 94 c3 80 e3 01 88 5d 02 41 83 fa 0a 0f 9c c3 80 e3 01 88 5d 03 c7 45 fc b6 ea 64 b3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_D_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 48 ff 0f af c8 f6 c1 01 0f 94 c1 83 3d 90 01 04 0a 0f 9c c0 08 c8 8b 0d 90 01 04 8b 15 90 01 04 8d 71 ff 89 f7 0f af f9 84 c0 75 48 83 e7 01 e9 96 90 00 } //10
		$a_00_1 = {48 c1 ed 20 01 e9 89 cd c1 ed 1f c1 f9 06 01 e9 89 cd c1 e5 07 01 d5 29 e9 89 ca 81 c2 f7 0f 00 00 48 63 d2 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}