
rule TrojanDownloader_BAT_Seraph_SW_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 01 00 00 0a 72 01 00 00 70 28 02 00 00 0a 6f 03 00 00 0a 0a 06 8e 69 8d 04 00 00 01 0b 16 0c 06 8e 69 17 59 0d 38 0e 00 00 00 07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee 07 13 04 dd 03 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}