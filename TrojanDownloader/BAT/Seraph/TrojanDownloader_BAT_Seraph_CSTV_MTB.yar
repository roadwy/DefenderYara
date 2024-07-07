
rule TrojanDownloader_BAT_Seraph_CSTV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.CSTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 04 0a dd 90 01 04 26 90 00 } //5
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 37 00 2f 00 } //1 http://80.66.75.37/
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}