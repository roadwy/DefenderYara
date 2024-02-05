
rule Trojan_Win32_Downloader_BT_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b c8 4e ad 4e 32 e1 8a c4 4a 52 4e aa 58 85 c0 75 07 8b 55 14 ff 75 10 5e 59 49 75 e0 } //00 00 
	condition:
		any of ($a_*)
 
}