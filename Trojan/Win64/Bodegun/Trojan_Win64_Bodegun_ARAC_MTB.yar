
rule Trojan_Win64_Bodegun_ARAC_MTB{
	meta:
		description = "Trojan:Win64/Bodegun.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 8b c0 48 8d 94 24 50 01 00 00 48 8d 4c 24 30 ff 15 ff 3c 00 00 4c 8d 8c 24 40 01 00 00 41 b8 00 80 00 00 48 8d 94 24 50 01 00 00 48 8b cf ff 15 a8 3d 00 00 85 c0 75 bc } //2
		$a_03_1 = {45 33 c9 4c 8b c3 48 8d 15 ?? 40 00 00 33 c9 ff 15 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}