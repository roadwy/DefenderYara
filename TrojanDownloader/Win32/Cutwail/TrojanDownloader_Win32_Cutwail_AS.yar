
rule TrojanDownloader_Win32_Cutwail_AS{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 05 0c 30 10 09 74 00 00 00 90 02 10 c7 05 90 01 01 30 10 09 00 40 00 00 90 02 10 64 a1 18 00 00 00 90 02 0a 8b 40 34 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}