
rule TrojanDownloader_BAT_Small_MV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 8d 11 00 00 01 25 16 72 50 03 00 70 a2 28 15 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}