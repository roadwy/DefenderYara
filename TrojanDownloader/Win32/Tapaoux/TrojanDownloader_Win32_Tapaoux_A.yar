
rule TrojanDownloader_Win32_Tapaoux_A{
	meta:
		description = "TrojanDownloader:Win32/Tapaoux.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 15 8b d7 47 81 fa 58 02 00 00 7f 0a 6a 64 ff 15 90 01 04 eb a9 8b 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}