
rule Trojan_Win32_Remcos_PI_MTB{
	meta:
		description = "Trojan:Win32/Remcos.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 65 73 74 2e 74 68 67 } //1 Test.thg
		$a_02_1 = {53 31 db 8b 04 8a 88 c7 88 e3 c1 e8 10 c1 e3 08 88 c3 89 1c 8a 49 79 ?? 5b 8b e5 5d c3 } //1
		$a_02_2 = {8b c8 8b 44 24 ?? 8b 50 ?? 03 d6 8b 44 24 ?? 8b 40 ?? 03 44 24 ?? e8 da d2 f8 ff 8b 44 24 ?? 8b 40 ?? 03 44 24 ?? 8b 54 24 ?? 89 42 ?? 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? 4b 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}