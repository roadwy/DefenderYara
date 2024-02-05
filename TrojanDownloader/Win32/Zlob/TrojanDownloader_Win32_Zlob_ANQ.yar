
rule TrojanDownloader_Win32_Zlob_ANQ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 84 24 3c 01 00 00 47 c6 84 24 3e 01 00 00 54 } //01 00 
		$a_01_1 = {c6 84 24 45 01 00 00 45 88 9c 24 47 01 00 00 ff 54 24 } //00 00 
	condition:
		any of ($a_*)
 
}