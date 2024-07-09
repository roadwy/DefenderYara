
rule Trojan_Win32_Emotet_AB{
	meta:
		description = "Trojan:Win32/Emotet.AB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c9 81 e9 fc a1 29 00 09 c8 83 e8 20 8d 15 78 97 40 00 89 1a 8d 0d b0 be 5c 00 89 fa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_AB_2{
	meta:
		description = "Trojan:Win32/Emotet.AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 54 8b 4c 24 54 8a 14 0d ?? ?? ?? ?? 2a 14 05 ?? ?? ?? ?? 8b 44 24 54 88 54 04 2c 8b 44 24 54 83 c0 01 89 44 24 50 83 f8 0e } //1
		$a_03_1 = {8b 44 24 58 89 c1 83 e1 0f 8b 54 24 78 81 f2 4c f4 df 03 8a 1c 0d ?? ?? ?? ?? 8a 3c 05 ?? ?? ?? ?? 28 df c7 44 24 7c ?? ?? ?? ?? 88 7c 04 38 01 d0 89 44 24 58 83 f8 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}