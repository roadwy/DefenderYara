
rule Trojan_Win32_Downloader_TB_MTB{
	meta:
		description = "Trojan:Win32/Downloader.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 0c 24 b9 90 01 04 31 c8 59 f7 d8 05 90 01 04 89 c1 90 00 } //01 00 
		$a_01_1 = {31 de 29 cb 31 fa 81 0f } //02 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}