
rule Ransom_MacOS_EvilQuest_D_MTB{
	meta:
		description = "Ransom:MacOS/EvilQuest.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 7d e4 04 0f 8d 3e 00 00 00 48 8b 45 f8 48 63 4d e4 0f b6 14 08 83 fa 00 0f 84 16 00 00 00 48 8b 45 f8 48 63 4d e4 8a 14 08 48 8b 45 e8 48 63 4d e4 88 14 08 e9 00 00 00 00 8b 45 e4 83 c0 01 89 45 e4 e9 b8 ff ff ff 48 8b 45 e8 48 83 c4 20 5d } //1
		$a_01_1 = {48 83 7d e8 00 0f 86 67 00 00 00 48 8b 45 e8 48 25 01 00 00 00 48 83 f8 01 0f 85 21 00 00 00 48 8b 45 d8 48 0f af 45 d0 8b 4d e4 89 ca 31 c9 48 89 55 c8 89 ca 48 8b 75 c8 48 f7 f6 48 89 55 d8 48 8b 45 e8 48 c1 e8 01 48 89 45 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}