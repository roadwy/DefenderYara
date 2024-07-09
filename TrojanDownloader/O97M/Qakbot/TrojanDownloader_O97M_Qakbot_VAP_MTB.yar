
rule TrojanDownloader_O97M_Qakbot_VAP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.VAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 69 6e 67 20 3d 20 22 39 37 2c 31 32 34 2c 31 31 36 2c 31 30 34 2c 31 30 37 2c 31 31 38 2c 39 37 2c 31 31 38 22 } //1 String = "97,124,116,104,107,118,97,118"
		$a_03_1 = {28 53 70 6c 69 74 28 [0-0f] 2c 20 22 2c 22 29 29 } //1
		$a_03_2 = {26 20 43 68 72 28 [0-0f] 28 [0-0f] 29 20 58 6f 72 20 34 29 } //1
		$a_01_3 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 .ShellExecute
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}