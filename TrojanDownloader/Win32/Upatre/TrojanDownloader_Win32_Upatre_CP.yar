
rule TrojanDownloader_Win32_Upatre_CP{
	meta:
		description = "TrojanDownloader:Win32/Upatre.CP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ad 2b c3 89 07 03 fa 49 75 f6 } //1
		$a_00_1 = {43 00 57 00 61 00 73 00 74 00 61 00 73 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}