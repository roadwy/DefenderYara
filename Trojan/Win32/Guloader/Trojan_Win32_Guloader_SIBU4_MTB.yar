
rule Trojan_Win32_Guloader_SIBU4_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU4!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 00 69 00 61 00 6e 00 74 00 44 00 6f 00 63 00 6b 00 } //01 00  GiantDock
		$a_03_1 = {cd 81 34 1a 90 01 04 90 02 30 43 90 02 35 43 90 02 40 43 90 02 25 43 90 02 35 81 fb 90 01 04 90 02 10 eb 20 90 02 25 0f 85 90 01 04 90 02 aa 81 2e 90 01 04 90 02 40 81 36 90 01 04 90 02 b5 ff d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}