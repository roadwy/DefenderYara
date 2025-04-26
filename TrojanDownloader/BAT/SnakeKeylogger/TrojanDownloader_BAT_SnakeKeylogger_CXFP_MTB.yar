
rule TrojanDownloader_BAT_SnakeKeylogger_CXFP_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeylogger.CXFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {77 00 77 00 77 00 2e 00 6c 00 6f 00 67 00 70 00 61 00 73 00 74 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 73 00 74 00 65 00 2f 00 72 00 61 00 77 00 2f 00 62 00 33 00 66 00 65 00 36 00 31 00 63 00 63 00 2d 00 65 00 35 00 63 00 63 00 2d 00 34 00 62 00 34 00 63 00 2d 00 39 00 66 00 33 00 33 00 2d 00 35 00 32 00 37 00 34 00 64 00 63 00 30 00 66 00 37 00 35 00 36 00 66 00 2e 00 74 00 78 00 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}