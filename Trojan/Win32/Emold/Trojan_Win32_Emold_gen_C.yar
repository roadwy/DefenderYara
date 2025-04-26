
rule Trojan_Win32_Emold_gen_C{
	meta:
		description = "Trojan:Win32/Emold.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 81 3f 4d 5a 75 ?? 8b 47 3c 89 fe 01 c7 66 81 3f 50 45 75 ?? 89 f0 } //1
		$a_01_1 = {00 31 6f 61 64 4c 69 62 72 61 72 79 41 00 } //1
		$a_03_2 = {28 07 30 07 47 e2 f9 eb 90 09 0a 00 bf ?? ?? ?? ?? b9 ?? ?? 00 00 } //2
		$a_03_3 = {6a 00 6a 00 ff 15 ?? ?? 40 00 31 c0 5f 5e 5b c9 c2 10 00 ff 15 ?? ?? 40 00 89 c3 b8 ?? ?? 00 00 28 d8 b9 ?? ?? 40 00 29 d9 ff e1 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=3
 
}