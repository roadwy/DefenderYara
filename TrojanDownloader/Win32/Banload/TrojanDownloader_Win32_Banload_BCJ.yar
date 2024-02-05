
rule TrojanDownloader_Win32_Banload_BCJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BCJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 0f 8e 47 01 00 00 33 c0 55 68 90 09 38 00 b8 90 01 04 e8 90 01 04 b8 90 01 04 ba 90 01 04 e8 90 01 04 b8 90 01 04 b9 90 01 04 8b 15 90 01 04 e8 90 01 04 a1 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}