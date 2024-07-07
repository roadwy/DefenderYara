
rule TrojanDownloader_BAT_Banload_L{
	meta:
		description = "TrojanDownloader:BAT/Banload.L,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 00 65 00 73 00 74 00 65 00 20 00 30 00 31 00 00 13 74 00 65 00 73 00 74 00 65 00 20 00 30 00 38 00 37 00 00 90 02 02 68 00 74 00 74 00 70 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}