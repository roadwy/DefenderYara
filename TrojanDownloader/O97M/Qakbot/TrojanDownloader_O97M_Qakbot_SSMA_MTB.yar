
rule TrojanDownloader_O97M_Qakbot_SSMA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SSMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-20] 2e 63 6f 6d 2f [0-0f] 2f [0-02] 2e 68 74 6d 6c } //1
		$a_03_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f [0-30] 2e 63 6f 6d 2f [0-0f] 2f [0-04] 2e 68 74 6d 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}