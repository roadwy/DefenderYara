
rule Trojan_Win32_Redosdru_V{
	meta:
		description = "Trojan:Win32/Redosdru.V,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 41 02 83 c1 04 8d b0 ff fe fe 7e f7 d0 33 f0 f7 c6 00 01 01 81 74 e8 } //1
		$a_03_1 = {66 81 38 4d 5a 57 74 08 ?? ?? ?? ?? ?? ?? ?? ?? 8b 78 3c 03 f8 89 7c 24 10 81 3f 50 45 00 00 74 08 } //1
		$a_01_2 = {8b 54 24 04 8a 1c 11 80 c3 7a 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 59 88 1c 11 41 3b c8 7c e1 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*5) >=6
 
}