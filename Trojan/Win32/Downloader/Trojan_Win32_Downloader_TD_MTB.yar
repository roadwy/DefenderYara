
rule Trojan_Win32_Downloader_TD_MTB{
	meta:
		description = "Trojan:Win32/Downloader.TD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 cb 01 cb 81 c2 90 01 04 01 fe 8b 3e 90 00 } //01 00 
		$a_03_1 = {29 d7 03 1e 31 f8 01 f1 89 ee b8 90 01 04 b9 90 01 04 81 c6 51 00 00 00 31 d8 2d 90 01 04 01 1e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}