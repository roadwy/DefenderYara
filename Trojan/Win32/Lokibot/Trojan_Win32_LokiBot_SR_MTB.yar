
rule Trojan_Win32_LokiBot_SR_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 e8 90 01 04 4b 75 90 01 01 6a 00 6a 00 6a 00 6a 00 6a 00 e8 90 01 04 bb 90 01 04 90 02 04 6a 00 6a 00 6a 00 6a 00 6a 00 e8 90 01 04 4b 90 00 } //1
		$a_03_1 = {8b c8 03 ca 73 05 e8 90 01 04 8a 09 90 02 04 80 f1 90 01 01 03 d0 73 05 e8 90 01 04 88 0a c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_LokiBot_SR_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 68 90 01 02 00 00 6a 00 e8 90 01 04 90 02 05 90 05 10 01 90 33 c0 89 90 01 02 be 90 01 04 bb 90 01 04 90 05 10 01 90 8b 90 02 03 03 90 01 02 90 05 10 01 90 8a 90 01 01 90 05 10 01 90 90 03 01 01 34 80 90 02 02 90 05 10 01 90 88 90 01 01 90 05 10 01 90 90 02 04 e8 90 01 04 90 05 10 01 90 43 4e 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_SR_MTB_3{
	meta:
		description = "Trojan:Win32/LokiBot.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 02 3c 61 72 90 02 04 3c 7a 77 90 02 04 2c 20 88 06 42 46 4b 90 00 } //1
		$a_03_1 = {b0 b7 8b 15 90 02 04 89 15 90 02 04 8b 15 90 02 04 8a 92 90 02 04 88 15 90 02 04 8b d6 03 d3 89 15 90 02 04 30 05 90 02 04 90 05 10 01 90 a0 90 02 04 8b 15 90 02 04 88 02 a1 90 02 04 a3 90 02 04 a1 90 02 04 83 c0 02 a3 90 02 04 90 05 10 01 90 43 81 fb 90 02 04 75 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}