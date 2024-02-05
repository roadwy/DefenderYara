
rule TrojanDownloader_Win32_Hagkite_A{
	meta:
		description = "TrojanDownloader:Win32/Hagkite.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 4c 04 50 40 83 f8 40 7c ed 68 90 01 04 e8 90 09 09 00 8a 88 90 01 04 80 f1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}