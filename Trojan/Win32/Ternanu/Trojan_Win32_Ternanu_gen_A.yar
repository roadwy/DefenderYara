
rule Trojan_Win32_Ternanu_gen_A{
	meta:
		description = "Trojan:Win32/Ternanu.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 b9 26 00 00 00 ba 0f 00 00 00 8b 03 e8 ?? ?? ?? ?? 6a 05 6a 00 } //2
		$a_01_1 = {6e 74 75 73 65 72 2e 6e 61 74 00 } //1
		$a_01_2 = {33 71 51 34 35 68 67 48 62 32 74 35 30 6d 75 47 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}