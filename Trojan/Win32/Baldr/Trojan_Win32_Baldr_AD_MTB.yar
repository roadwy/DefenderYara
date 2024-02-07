
rule Trojan_Win32_Baldr_AD_MTB{
	meta:
		description = "Trojan:Win32/Baldr.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cf 33 d2 6a 90 01 01 8b c1 5e f7 f6 8a 44 15 90 01 01 30 81 90 01 04 41 81 f9 90 01 04 72 90 00 } //01 00 
		$a_00_1 = {61 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 } //00 00  av4.0.30319
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}