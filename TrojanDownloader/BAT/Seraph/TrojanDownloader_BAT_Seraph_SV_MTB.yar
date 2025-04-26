
rule TrojanDownloader_BAT_Seraph_SV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 04 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 05 dd 27 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule TrojanDownloader_BAT_Seraph_SV_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 6f 03 00 00 0a 13 25 11 0c 11 25 11 15 59 61 13 0c 11 15 19 11 0c 58 1e 63 59 13 15 11 0d 6f 37 00 00 06 2d d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanDownloader_BAT_Seraph_SV_MTB_3{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 08 09 06 09 91 7e 01 00 00 04 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1 } //2
		$a_01_1 = {47 6e 66 6f 6a 61 65 71 6a 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 Gnfojaeqjl.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}