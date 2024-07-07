
rule TrojanDownloader_BAT_Lenwadu_C_bit{
	meta:
		description = "TrojanDownloader:BAT/Lenwadu.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6e 00 64 00 61 00 6e 00 63 00 65 00 6b 00 61 00 72 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 90 02 30 2e 00 65 00 78 00 65 00 90 00 } //1
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}