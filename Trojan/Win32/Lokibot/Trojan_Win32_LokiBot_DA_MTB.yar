
rule Trojan_Win32_LokiBot_DA_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 16 88 15 ?? ?? ?? ?? 30 05 ?? ?? ?? ?? 90 05 10 01 90 a0 ?? ?? ?? ?? e8 42 ?? ?? ?? ?? 90 05 10 01 90 ff 05 ?? ?? ?? ?? 90 05 10 01 90 46 4b 75 b3 90 05 10 01 90 81 c7 } //1
		$a_03_1 = {bb 01 00 00 00 90 05 10 01 90 8b d0 03 d3 90 05 10 01 90 c6 02 0b 90 05 10 01 90 43 81 fb ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}