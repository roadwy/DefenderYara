
rule Trojan_Win64_EmotetCrypt_PB_MTB{
	meta:
		description = "Trojan:Win64/EmotetCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 03 c8 48 63 05 90 01 04 48 03 c8 48 63 05 90 01 04 48 2b c8 48 63 05 90 01 04 48 2b c8 48 8b 44 90 01 02 0f b6 04 08 03 44 24 30 41 8b d0 33 d0 8b 0d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_EmotetCrypt_PB_MTB_2{
	meta:
		description = "Trojan:Win64/EmotetCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 33 c9 0f 1f 40 00 66 0f 1f 84 90 02 06 0f 10 81 90 01 04 0f 28 ca 66 0f ef c8 0f 11 89 90 01 04 0f 10 81 90 01 04 0f 28 ca 66 0f ef c8 0f 11 89 90 01 04 0f 10 81 90 01 04 0f 28 ca 66 0f ef c8 0f 11 89 90 01 04 0f 10 81 f8 b9 43 00 0f 28 ca 66 0f ef c8 0f 11 89 90 01 04 83 c1 90 01 01 81 f9 90 01 04 7c a1 81 f9 90 01 04 7d 90 01 01 8d 81 90 01 04 0f 1f 00 80 30 90 01 01 40 3d 90 01 04 7c 90 00 } //2
		$a_01_1 = {4b 49 4c 4c 45 52 31 } //1 KILLER1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}