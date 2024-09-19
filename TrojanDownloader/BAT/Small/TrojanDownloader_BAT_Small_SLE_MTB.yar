
rule TrojanDownloader_BAT_Small_SLE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.SLE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 72 63 00 00 70 02 6f 1c 00 00 0a 26 00 de 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}