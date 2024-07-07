
rule TrojanDownloader_BAT_Reline_GM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Reline.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {73 0b 00 00 0a 0a 06 90 02 40 6f 0c 00 00 0a 06 90 02 40 6f 0c 00 00 0a 06 6f 0d 00 00 0a 0d 2b 34 90 00 } //1
		$a_00_1 = {12 03 28 0e 00 00 0a 0b 73 0f 00 00 0a 0c 08 07 28 04 00 00 06 6f 10 00 00 0a 08 16 6f 11 00 00 0a 08 16 6f 12 00 00 0a 08 28 13 00 00 0a 26 de 03 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}