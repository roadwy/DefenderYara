
rule TrojanDownloader_Linux_Mirai_J_MTB{
	meta:
		description = "TrojanDownloader:Linux/Mirai.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {04 e0 2d e5 00 10 a0 e1 04 d0 4d e2 01 00 a0 e3 ad 00 00 eb 04 d0 8d e2 04 e0 9d e4 1e ff 2f e1 04 e0 2d e5 00 10 a0 e1 04 d0 4d e2 06 00 a0 e3 a5 00 00 eb 04 d0 8d e2 04 e0 9d e4 1e ff 2f e1 } //01 00 
		$a_00_1 = {0d c0 a0 e1 f0 00 2d e9 00 70 a0 e1 01 00 a0 e1 02 10 a0 e1 03 20 a0 e1 78 00 9c e8 00 00 00 ef f0 00 bd e8 01 0a 70 e3 0e f0 a0 31 ff ff ff ea } //00 00 
	condition:
		any of ($a_*)
 
}