
rule Trojan_Win32_Downloader_BS_MTB{
	meta:
		description = "Trojan:Win32/Downloader.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ad 51 8b 0f 4e 4e 33 c1 aa 4a 4e 8b c2 85 c0 75 07 ff 75 10 8b 55 14 5e 59 49 75 e4 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}