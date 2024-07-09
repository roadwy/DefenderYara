
rule TrojanDownloader_O97M_Qakbot_RSA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RSA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {65 6c 69 74 65 62 6c 6f 67 73 70 6f 74 2e 63 6f 6d 2f 64 73 2f 30 37 30 32 2e 67 69 66 90 0a 30 00 4b 65 72 6e 65 6c 33 32 25 ?? ?? 68 74 74 70 73 3a 2f 2f } //5
		$a_02_1 = {73 79 69 66 61 62 69 6f 64 65 72 6d 61 2e 63 6f 6d 2f 64 73 2f 30 39 30 32 2e 67 69 66 90 0a 30 00 4b 65 72 6e 65 6c 33 32 25 ?? ?? 68 74 74 70 73 3a 2f 2f } //5
		$a_00_2 = {5c 69 6f 6a 68 73 66 67 76 2e 64 76 65 72 73 } //1 \iojhsfgv.dvers
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_00_2  & 1)*1) >=6
 
}