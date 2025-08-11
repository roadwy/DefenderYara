
rule Trojan_Win64_CoinMiner_KK_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 00 70 00 70 00 65 00 70 00 7a 00 7d 00 7f 00 60 00 0f 00 7e 00 62 00 61 00 60 00 67 00 60 00 13 00 14 00 12 00 1b 00 6e 00 27 00 5b 00 00 00 67 42 5b 7d 57 4e 5e 4e 7e 4c 56 34 28 21 22 28 } //6
		$a_03_1 = {8b c2 c1 e8 1f 03 d0 0f b7 c2 6b d0 ?? 41 0f b7 c2 41 ff c2 66 2b c2 66 83 c0 ?? 66 31 41 fe 41 83 fa 1d } //2
		$a_03_2 = {4c 8d 85 a8 04 00 00 49 83 fb 0f 4d 0f 47 c2 49 8b cd 48 83 3d ?? 0e 05 00 0f 48 0f 47 0d ?? ?? 05 00 33 d2 49 8b c1 48 f7 35 ?? ?? 05 00 48 03 d1 48 8d 8d 38 05 00 00 48 83 bd 50 05 00 00 0f 48 0f 47 8d 38 05 00 00 43 0f b6 04 08 32 02 42 88 04 09 49 ff c1 4c 3b cb } //3
		$a_01_3 = {78 61 69 38 33 30 6b 2e 63 6f 6d } //1 xai830k.com
	condition:
		((#a_01_0  & 1)*6+(#a_03_1  & 1)*2+(#a_03_2  & 1)*3+(#a_01_3  & 1)*1) >=6
 
}