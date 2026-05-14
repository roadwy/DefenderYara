
rule TrojanDownloader_Win32_Carberp_AMTB{
	meta:
		description = "TrojanDownloader:Win32/Carberp!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 36 32 2e 36 30 2e 32 32 36 2e 31 35 39 2f 67 65 74 65 72 2f 69 6e 64 65 78 2e 70 68 70 3f } //http://62.60.226.159/geter/index.php?  2
	condition:
		((#a_80_0  & 1)*2) >=2
 
}