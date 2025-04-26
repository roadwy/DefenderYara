
rule Trojan_BAT_Downloader_SQ_MTB{
	meta:
		description = "Trojan:BAT/Downloader.SQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 32 72 27 00 00 70 2b 32 2b 37 2b 3c 17 2d 17 26 2b 3d 16 2b 3d 8e 69 1b 2d 12 26 26 26 2b 36 2b 37 dd 5b 00 00 00 0b 15 2c f3 2b e4 28 2e 00 00 0a 2b ea 28 2f 00 00 0a 2b c7 28 0e 00 00 06 2b c7 6f 30 00 00 0a 2b c2 28 31 00 00 0a 2b bd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}