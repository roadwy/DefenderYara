
rule TrojanDownloader_BAT_Gendwnurl_QQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {07 09 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 58 b5 0c 08 11 04 13 05 11 05 31 d1 } //10
		$a_80_1 = {61 64 64 5f 53 68 75 74 64 6f 77 6e } //add_Shutdown  3
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 61 73 73 65 74 73 } //Downloading assets  3
		$a_80_3 = {2f 49 73 61 73 73 2e 65 78 65 } ///Isass.exe  3
		$a_80_4 = {5c 55 73 65 72 73 5c 4d 61 73 74 65 72 48 79 } //\Users\MasterHy  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}