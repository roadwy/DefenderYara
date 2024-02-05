
rule Trojan_Win32_Downloader_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0b 5d 00 3d a6 00 00 00 83 fb 75 e8 90 02 10 90 13 90 02 20 01 1c 38 90 02 20 90 13 90 02 10 81 ef 90 02 20 90 13 90 02 10 81 c7 90 02 10 0f 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}