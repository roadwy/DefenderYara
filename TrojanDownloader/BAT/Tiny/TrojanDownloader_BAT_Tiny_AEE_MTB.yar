
rule TrojanDownloader_BAT_Tiny_AEE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AEE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 1a 00 00 00 07 00 00 00 05 00 00 00 11 00 00 00 03 00 00 00 24 00 00 00 2a 00 00 00 0c 00 00 00 02 00 00 00 05 00 00 00 05 00 00 00 08 00 00 00 01 00 00 00 03 00 00 00 02 00 00 00 03 00 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}