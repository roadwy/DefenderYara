
rule TrojanDownloader_O97M_Qakbot_PDN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 72 64 69 73 6f 73 2e 63 6f 6d 2f 39 62 56 41 61 30 36 57 58 7a 73 6a 2f 4b 6e 68 66 6e 2e 70 6e 67 } //1 ordisos.com/9bVAa06WXzsj/Knhfn.png
		$a_01_1 = {6e 63 65 6c 6c 74 65 63 68 2e 63 6f 6d 2f 71 56 46 6d 45 34 4d 35 42 52 2f 4b 6e 68 66 6e 2e 70 6e 67 } //1 ncelltech.com/qVFmE4M5BR/Knhfn.png
		$a_01_2 = {64 65 63 6f 32 68 6b 2e 63 6f 6d 2f 65 68 33 64 4b 42 53 50 53 36 2f 4b 6e 68 66 6e 2e 70 6e 67 } //1 deco2hk.com/eh3dKBSPS6/Knhfn.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}