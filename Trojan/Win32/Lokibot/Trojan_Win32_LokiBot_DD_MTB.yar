
rule Trojan_Win32_LokiBot_DD_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c7 8b de 8b d3 e8 ?? ?? ff ff 90 90 90 05 10 01 90 46 81 fe ?? ?? 00 00 75 } //1
		$a_02_1 = {8b c8 03 ca 8b c2 b2 ?? 32 90 90 ?? ?? ?? 00 88 11 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_LokiBot_DD_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 03 01 00 00 00 90 05 10 01 90 8b d0 03 13 90 05 10 01 90 c6 02 ?? 90 05 10 01 90 ff 03 81 3b ?? ?? ?? ?? 75 } //1
		$a_03_1 = {8b 03 8a 80 ?? ?? ?? ?? a2 ?? ?? ?? ?? 90 05 10 01 90 b0 6b 90 05 10 01 90 30 05 ?? ?? ?? ?? 90 05 10 01 90 a0 ?? ?? ?? ?? e8 ?? ?? ?? ?? 90 05 10 01 90 8b 07 40 89 07 90 05 10 01 90 ff ?? 81 3b ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}