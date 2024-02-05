
rule Trojan_Win32_Downloader_RPD_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff d6 68 dc 05 00 00 8b f8 ff 15 90 01 04 ff d6 2b c7 3d dc 05 00 00 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}