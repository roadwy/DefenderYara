
rule Trojan_Win32_Downloader_BX_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 10 29 f3 40 89 db 39 f8 75 eb } //00 00 
	condition:
		any of ($a_*)
 
}