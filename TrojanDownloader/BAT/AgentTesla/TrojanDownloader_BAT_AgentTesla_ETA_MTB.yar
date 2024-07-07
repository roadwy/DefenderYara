
rule TrojanDownloader_BAT_AgentTesla_ETA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ETA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 00 73 00 61 00 66 00 64 00 61 00 73 00 64 00 66 00 46 00 44 00 53 00 41 00 46 00 41 00 44 00 53 00 46 00 41 00 53 00 } //1 dsafdasdfFDSAFADSFAS
		$a_01_1 = {a4 e1 7c 3a 39 30 cc d4 d8 3c ad ef 56 ca b3 11 eb 55 e7 83 42 ba 4d 46 8f 82 e8 22 c4 80 6b 16 02 32 83 12 33 55 96 e2 0c 4a 33 93 de 61 47 3f } //1
		$a_01_2 = {00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00 } //1 䐀睯汮慯䑤瑡a
		$a_01_3 = {00 47 65 74 54 79 70 65 00 } //1
		$a_01_4 = {00 47 65 74 4d 65 74 68 6f 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}