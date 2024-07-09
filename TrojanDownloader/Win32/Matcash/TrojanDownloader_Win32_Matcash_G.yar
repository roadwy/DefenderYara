
rule TrojanDownloader_Win32_Matcash_G{
	meta:
		description = "TrojanDownloader:Win32/Matcash.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 00 [0-05] 70 3a 2f [0-15] 2e 6d [0-05] 63 62 [0-05] 6f [0-05] 6f [0-05] 2e [0-05] 63 6f [0-05] 6d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}