
rule Trojan_Win32_Redline_GFA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 45 e0 8b 4d e0 2b 4d c4 8b 45 c4 33 45 94 0f af c8 8b 45 e0 0f af 45 e0 0f af 45 c4 69 c0 06 03 00 00 3b c1 74 34 8a 45 dd 88 45 cd } //10
		$a_01_1 = {66 89 44 24 10 8a 4c 24 0b 8a 44 24 0c 33 c8 8a 44 24 0b 2b c1 88 44 24 0b } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}