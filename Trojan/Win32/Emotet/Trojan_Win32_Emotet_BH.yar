
rule Trojan_Win32_Emotet_BH{
	meta:
		description = "Trojan:Win32/Emotet.BH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 3c 8a 0c 05 ?? ?? ?? ?? 8b 54 24 20 81 f2 ?? ?? ?? ?? 8a 2c 05 ?? ?? ?? ?? 28 cd 89 94 24 9c 00 00 00 88 6c 04 48 83 c0 01 89 44 24 3c 83 f8 0e } //1
		$a_03_1 = {88 54 24 0b 89 f2 8b 74 24 10 f7 f6 8b 74 24 20 89 4c 24 04 8a 0c 3e 8b 7c 24 0c 8a 2c 17 28 e9 8a 54 24 0b 80 c2 01 8b 74 24 1c 88 0c 1e 8b 5c 24 38 30 ea 8b 8c 24 ?? ?? ?? ?? 8b 74 24 28 d3 ee 89 b4 24 ?? ?? ?? ?? 88 13 8b 74 24 04 03 74 24 30 89 74 24 2c 8b 5c 24 28 39 de } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}