
rule TrojanDownloader_Win32_Renos_OD{
	meta:
		description = "TrojanDownloader:Win32/Renos.OD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 00 3c 8b 74 90 01 01 eb 90 14 3c 55 75 90 00 } //01 00 
		$a_03_1 = {8a 00 20 db 3c 8b 5b 74 90 01 01 eb 90 14 3c 55 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}