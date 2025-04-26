
rule TrojanDownloader_O97M_Qakbot_PDD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 66 76 72 6d 63 6c 65 61 6e 69 6e 67 2e 63 6f 6d 2f 62 4d 56 32 70 7a 4d 49 2f 30 39 30 33 32 32 2e 67 69 66 } //1 ://fvrmcleaning.com/bMV2pzMI/090322.gif
		$a_01_1 = {3a 2f 2f 66 69 6f 72 65 77 6c 6b 66 69 78 2e 67 71 2f 58 6a 4c 69 54 66 67 59 6e 2f 30 39 30 33 32 32 2e 67 69 66 } //1 ://fiorewlkfix.gq/XjLiTfgYn/090322.gif
		$a_01_2 = {3a 2f 2f 6b 73 69 6e 64 65 73 69 67 6e 2e 63 6f 6d 2e 62 72 2f 34 58 57 4c 51 30 49 74 7a 2f 30 39 30 33 32 32 2e 67 69 66 } //1 ://ksindesign.com.br/4XWLQ0Itz/090322.gif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}