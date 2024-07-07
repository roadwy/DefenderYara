
rule Trojan_Win64_CherryLoader_RX_MTB{
	meta:
		description = "Trojan:Win64/CherryLoader.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c6 48 b8 ab aa aa aa aa aa aa aa 48 89 d7 48 f7 eb 48 01 da 48 d1 fa 48 8d 14 52 48 89 d8 48 29 d0 0f b6 14 1f 48 83 f8 03 72 b9 } //5
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 34 70 6e 6e 4e 37 49 64 4e 4b 6a 7a 48 75 4f 45 4c 59 46 4d 2f 75 46 7a 62 34 6c 54 46 6b 34 56 78 65 63 6d 77 58 4a 6e 6c 2f 50 71 6c 2d 76 46 39 6b 53 5a 76 6a 76 65 55 6a 4c 53 64 32 2f 77 66 2d 56 46 54 67 38 50 62 54 4c 38 32 74 65 56 68 47 30 } //1 Go build ID: "4pnnN7IdNKjzHuOELYFM/uFzb4lTFk4VxecmwXJnl/Pql-vF9kSZvjveUjLSd2/wf-VFTg8PbTL82teVhG0
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}