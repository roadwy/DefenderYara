
rule Trojan_Win32_LokiBot_DE_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b0 c0 8b 15 90 01 04 89 16 8b d3 90 05 10 01 90 03 15 90 01 04 89 15 90 01 04 90 05 10 01 90 8b 16 8a 92 90 01 04 88 15 90 01 04 30 05 90 01 04 90 05 10 01 90 a0 90 01 04 8b 15 90 01 04 89 16 e8 90 01 04 90 05 10 01 90 a1 90 01 04 89 06 90 05 10 01 90 8b 06 83 c0 02 a3 90 01 04 43 81 90 00 } //01 00 
		$a_01_1 = {bb db 7c b9 0d 90 4b 75 fc } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}