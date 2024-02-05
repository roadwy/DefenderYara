
rule Trojan_Win32_Downloader_BR_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 a4 8a 4d da 80 f1 59 88 4d da 8b 55 84 39 d0 0f 84 } //01 00 
		$a_03_1 = {31 c7 89 7d 90 01 01 39 d1 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}