
rule Trojan_Win32_LokiBot_SR_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 4b 75 ?? 6a 00 6a 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? bb ?? ?? ?? ?? [0-04] 6a 00 6a 00 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 4b } //1
		$a_03_1 = {8b c8 03 ca 73 05 e8 ?? ?? ?? ?? 8a 09 [0-04] 80 f1 ?? 03 d0 73 05 e8 ?? ?? ?? ?? 88 0a c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_LokiBot_SR_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? [0-05] 90 05 10 01 90 33 c0 89 ?? ?? be ?? ?? ?? ?? bb ?? ?? ?? ?? 90 05 10 01 90 8b [0-03] 03 ?? ?? 90 05 10 01 90 8a ?? 90 05 10 01 90 (34|80) [0-02] 90 05 10 01 90 88 ?? 90 05 10 01 90 [0-04] e8 ?? ?? ?? ?? 90 05 10 01 90 43 4e 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_SR_MTB_3{
	meta:
		description = "Trojan:Win32/LokiBot.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 02 3c 61 72 [0-04] 3c 7a 77 [0-04] 2c 20 88 06 42 46 4b } //1
		$a_03_1 = {b0 b7 8b 15 [0-04] 89 15 [0-04] 8b 15 [0-04] 8a 92 [0-04] 88 15 [0-04] 8b d6 03 d3 89 15 [0-04] 30 05 [0-04] 90 05 10 01 90 a0 [0-04] 8b 15 [0-04] 88 02 a1 [0-04] a3 [0-04] a1 [0-04] 83 c0 02 a3 [0-04] 90 05 10 01 90 43 81 fb [0-04] 75 a1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}