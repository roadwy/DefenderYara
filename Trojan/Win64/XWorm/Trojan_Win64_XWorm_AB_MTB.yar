
rule Trojan_Win64_XWorm_AB_MTB{
	meta:
		description = "Trojan:Win64/XWorm.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 94 24 20 02 00 00 b9 04 01 00 00 4c 89 54 24 50 4c 89 d2 ff 15 ?? 7b 00 00 85 c0 0f 84 ?? 00 00 00 45 31 c0 48 8b 4c 24 50 4c 8d a4 24 30 03 00 00 [0-0f] 00 00 ff 15 ?? 7b 00 00 85 c0 0f 84 ?? 00 00 00 ba 2e 00 00 00 4c 89 e1 e8 ?? 16 00 00 48 85 c0 74 10 48 8d 15 [0-02] 00 00 48 89 c1 ff 15 [0-02] 00 00 45 31 d2 } //6
		$a_03_1 = {53 48 83 ec 58 65 48 8b 04 25 30 00 00 00 48 8b 70 08 48 8b 1d ?? 44 00 00 48 8b 3d 6d 83 00 00 eb 13 0f 1f 00 48 39 c6 0f 84 af 00 00 00 b9 e8 03 00 00 ff d7 31 c0 f0 48 0f b1 33 75 e7 } //6
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*6) >=12
 
}