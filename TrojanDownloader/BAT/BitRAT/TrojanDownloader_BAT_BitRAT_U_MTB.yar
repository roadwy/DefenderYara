
rule TrojanDownloader_BAT_BitRAT_U_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 06 20 90 01 03 2c 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 26 20 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}