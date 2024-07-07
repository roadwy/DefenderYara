
rule TrojanDownloader_BAT_AsyncRAT_SL_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 18 d8 0a 06 1f 18 fe 02 0d 09 2c 03 1f 18 0a 00 06 1f 18 5d 16 fe 03 13 04 11 04 2d e2 } //2
		$a_81_1 = {6e 6e 6e 2e 65 78 65 } //2 nnn.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}