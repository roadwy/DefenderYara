
rule TrojanDownloader_BAT_AsyncRAT_SO_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 20 0d 96 01 00 13 05 20 0d 96 01 00 13 06 00 2b 41 00 20 0d 96 01 00 13 07 20 0d 96 01 00 13 08 20 5a e4 01 00 13 09 11 09 20 a3 1c 03 00 fe 01 13 0a 11 0a 2c 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}