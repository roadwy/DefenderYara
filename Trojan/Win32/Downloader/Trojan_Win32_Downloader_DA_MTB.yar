
rule Trojan_Win32_Downloader_DA_MTB{
	meta:
		description = "Trojan:Win32/Downloader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 45 ec 8b 45 ec 8a 04 30 8b 0d 90 02 04 88 04 31 83 3d 90 02 04 44 75 1d 90 00 } //02 00 
		$a_01_1 = {3d 35 79 02 0f 7f 08 40 3d e2 51 62 73 7c f1 } //00 00 
	condition:
		any of ($a_*)
 
}