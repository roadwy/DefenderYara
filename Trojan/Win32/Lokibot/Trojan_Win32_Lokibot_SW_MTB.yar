
rule Trojan_Win32_Lokibot_SW_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 90 05 10 01 90 8b c2 03 c3 90 05 10 01 90 c6 00 90 01 01 90 05 10 01 90 43 81 fb 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {8b 34 24 03 f7 90 05 10 01 90 8a 08 90 05 10 01 90 80 f1 90 01 01 90 05 10 01 90 88 0e 90 05 10 01 90 47 90 05 10 01 90 40 4a 75 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}