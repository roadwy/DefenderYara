
rule Trojan_Win32_ClipBanker_NITA_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 6a 02 e8 c9 f6 05 00 8b f8 83 ff ff 74 7d 8d 4c 24 28 51 57 c7 44 24 30 2c 02 00 00 e8 a9 f6 05 00 3b c3 74 5f 8b 2d 88 52 50 00 8b 44 24 14 3b c3 75 05 b8 d0 6a 50 00 50 8d 54 24 50 52 e8 f5 24 04 00 83 c4 08 85 c0 75 27 8b 44 24 30 50 53 68 ff 0f 1f 00 ff d5 8b f0 3b f3 74 0f 53 56 ff 15 8c 52 50 00 56 ff 15 88 53 50 00 be 01 00 00 00 8d 4c 24 28 51 57 e8 48 f6 05 00 3b c3 } //2
		$a_01_1 = {56 57 8b f1 8b 46 20 6a 64 50 ff 15 08 56 50 00 8d 7e 74 68 84 60 50 00 57 e8 82 ff ff ff 83 c4 08 8d 4e 7c 84 c0 74 07 68 64 60 50 00 eb 05 68 40 60 50 00 e8 ca 3f 0a 00 68 84 60 50 00 57 e8 5c ff ff ff 83 c4 08 84 c0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}