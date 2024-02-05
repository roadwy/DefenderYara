
rule Trojan_Win32_Downloader_RPP_MTB{
	meta:
		description = "Trojan:Win32/Downloader.RPP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0c 07 66 f7 c1 00 00 f7 c3 00 00 00 00 66 f7 c6 00 00 f7 c2 00 00 00 00 81 f1 af 58 73 c9 66 f7 c7 00 00 66 f7 c7 00 00 a9 00 00 00 00 31 0c 06 } //00 00 
	condition:
		any of ($a_*)
 
}