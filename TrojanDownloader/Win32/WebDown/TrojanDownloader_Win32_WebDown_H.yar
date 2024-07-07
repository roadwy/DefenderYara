
rule TrojanDownloader_Win32_WebDown_H{
	meta:
		description = "TrojanDownloader:Win32/WebDown.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 24 20 40 00 6a 00 6a 00 e8 53 00 00 00 68 00 01 00 00 68 90 01 02 40 00 6a 00 e8 30 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}