
rule Trojan_Win32_Oficla_O{
	meta:
		description = "Trojan:Win32/Oficla.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 45 f4 64 c6 45 f5 25 (83 c0 78|8d 44 49 03 8d 04 80 c1 e0 03) 88 45 f6 c6 45 f7 00 c7 44 24 0c ?? ?? ?? ?? c7 44 24 08 ?? ?? ?? ?? 8d 45 f3 89 44 24 04 } //1
		$a_01_1 = {00 69 6e 74 72 6f 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e 00 } //1
		$a_01_2 = {32 30 30 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 65 73 74 61 62 6c 69 73 68 65 64 0d 0a 0d 0a 00 50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 00 47 45 54 00 50 4f 53 54 00 50 55 54 00 48 45 41 44 00 43 4f 4e 4e 45 43 54 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}