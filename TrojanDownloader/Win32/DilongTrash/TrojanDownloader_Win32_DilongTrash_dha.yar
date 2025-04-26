
rule TrojanDownloader_Win32_DilongTrash_dha{
	meta:
		description = "TrojanDownloader:Win32/DilongTrash!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_43_0 = {73 14 00 00 0a 0a 02 7b 01 00 00 04 17 06 17 1b 6f 90 01 04 d2 9c 02 7b 01 00 00 04 1b 06 17 1f 09 6f 90 01 04 d2 9c 02 7b 01 00 00 04 1f 7b 06 17 1f 09 6f 90 01 04 d2 9c 2a 90 00 00 } //1
	condition:
		((#a_43_0  & 1)*1) >=1
 
}