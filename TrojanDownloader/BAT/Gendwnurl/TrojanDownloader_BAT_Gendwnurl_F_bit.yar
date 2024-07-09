
rule TrojanDownloader_BAT_Gendwnurl_F_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.F!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 58 b5 0c } //1
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 } //1 DownloadFile
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}