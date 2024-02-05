
rule TrojanDownloader_Win32_Matcash_G{
	meta:
		description = "TrojanDownloader:Win32/Matcash.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 00 90 02 05 70 3a 2f 90 02 15 2e 6d 90 02 05 63 62 90 02 05 6f 90 02 05 6f 90 02 05 2e 90 02 05 63 6f 90 02 05 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}