
rule Trojan_Win32_LokiBot_DW_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 d2 0f 84 90 02 20 bb 01 00 00 00 90 02 20 43 81 fb 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {53 56 57 e8 90 02 30 b0 90 01 01 90 05 10 01 90 8b 90 01 01 90 05 10 01 90 81 fa 90 01 02 00 00 90 02 10 8a 92 90 01 04 90 05 05 01 90 32 d0 90 02 10 e8 90 02 15 81 fb 90 01 02 00 00 75 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}