
rule Trojan_Win32_Downloader_TC_MTB{
	meta:
		description = "Trojan:Win32/Downloader.TC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {39 d2 74 01 ea 31 3e 01 c1 21 c0 81 c6 04 00 00 00 01 c8 81 c1 90 01 04 39 d6 75 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}