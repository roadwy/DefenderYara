
rule Trojan_Win32_lokiBot_DF_MTB{
	meta:
		description = "Trojan:Win32/lokiBot.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 f6 b3 37 a1 90 01 04 89 07 8b c6 03 05 90 01 04 a3 90 01 04 8b 07 8a 80 90 01 04 a2 90 01 04 90 05 10 01 90 8b d3 a0 90 01 04 e8 90 01 04 a2 90 01 04 8a 1d 90 01 04 a1 90 01 04 89 07 8b c3 e8 90 01 04 90 05 10 01 90 a1 90 01 04 89 07 90 05 10 01 90 8b 07 83 c0 02 a3 90 01 04 90 05 10 01 90 46 81 fe 90 01 04 75 90 00 } //1
		$a_03_1 = {55 8b ec ff 75 0c 8a 45 08 90 05 10 01 90 5f 30 07 5d c2 08 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}