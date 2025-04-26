
rule Trojan_Win32_Urocflood_A{
	meta:
		description = "Trojan:Win32/Urocflood.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 69 2e 25 69 2e 25 69 2e 25 69 00 } //1
		$a_03_1 = {68 39 05 00 00 66 89 46 02 ff ?? ?? ?? ?? 00 68 39 05 00 00 89 46 04 ff ?? ?? ?? ?? 00 68 39 05 00 00 89 46 08 66 c7 46 0c 50 02 ff ?? ?? ?? ?? 00 8b 55 08 66 89 46 0e } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}