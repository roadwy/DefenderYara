
rule Trojan_Win32_Refpron_gen_B{
	meta:
		description = "Trojan:Win32/Refpron.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {66 05 bf 58 90 09 0b 00 [0-06] 66 69 ?? 6d ce } //1
		$a_03_1 = {c7 40 0c c8 20 00 00 ba c0 d4 01 00 8b 45 ?? e8 } //2
		$a_03_2 = {68 0d ba db 00 8b 45 f0 50 e8 ?? ?? ff ff 89 45 ?? 81 7d ?? 02 01 00 00 75 } //1
		$a_03_3 = {68 0d ba db 00 56 e8 ?? ?? ff ff 3d 02 01 00 00 75 } //1
		$a_01_4 = {63 00 00 00 02 00 00 00 5c 00 00 00 02 00 00 00 50 00 00 00 02 00 00 00 68 00 00 00 02 00 00 00 79 00 00 00 02 00 00 00 73 00 00 00 02 00 00 00 61 00 00 00 02 00 00 00 6c 00 00 00 02 00 00 00 4d 00 00 00 02 00 00 00 6d 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 72 00 } //1
		$a_02_5 = {00 53 65 74 20 90 0e 04 00 46 69 6c 65 20 90 0e 04 00 54 69 6d 65 20 90 0e 04 00 53 75 63 63 65 73 73 66 75 6c 6c 79 21 21 21 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1) >=3
 
}