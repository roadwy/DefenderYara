
rule Trojan_Win32_Wazabre_A{
	meta:
		description = "Trojan:Win32/Wazabre.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 1e 8b 7d f4 8b 75 fc 81 7c 37 fc fe fe fe fe 75 0e ff 75 1c ff 75 e4 e8 } //1
		$a_03_1 = {66 c7 05 02 70 40 00 06 00 66 c7 05 06 70 40 00 11 00 66 c7 05 08 70 40 00 12 00 66 c7 05 0a 70 40 00 25 00 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}