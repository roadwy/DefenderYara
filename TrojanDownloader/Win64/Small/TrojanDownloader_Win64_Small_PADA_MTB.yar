
rule TrojanDownloader_Win64_Small_PADA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Small.PADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 41 0f 6e d0 66 0f 70 d2 00 66 0f fe d5 66 0f 6f ca 66 0f 62 ca 66 0f 38 28 cc 66 0f 6f c2 66 0f 6a c2 66 0f 38 28 c4 0f c6 c8 dd 66 0f e2 ce 66 0f 6f c1 66 41 0f d2 c0 66 0f fe c1 66 0f 38 40 c7 66 0f fa d0 f2 0f 70 c2 d8 f3 0f 70 c8 d8 66 0f 70 d1 d8 0f 54 15 c3 d8 07 00 66 0f 67 d2 66 0f 6e c2 66 0f fc d0 66 0f 6e 41 fc 0f 57 d0 66 0f 7e 51 fc } //01 00 
		$a_01_1 = {66 0f 6f c1 66 41 0f d2 c0 66 0f fe c1 66 0f 38 40 c7 66 0f fa d8 f2 0f 70 c3 d8 f3 0f 70 c8 d8 66 0f 70 d1 d8 0f 54 15 4b d8 07 00 66 0f 67 d2 66 0f 6e c2 66 0f fc d0 66 0f 6e 01 0f 57 d0 66 0f 7e 11 41 83 c0 08 48 8d 49 08 41 83 f8 10 } //00 00 
	condition:
		any of ($a_*)
 
}