
rule Trojan_Win32_Tracur_gen_A{
	meta:
		description = "Trojan:Win32/Tracur.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_0b_0 = {81 fa 22 67 3f 7a 74 ?? 81 fa 67 22 7a 3f 0f 84 ?? ?? 00 00 } //1
		$a_0b_1 = {81 fa 30 75 2d 68 0f 84 ?? ?? 00 00 81 fa 3e 7b 23 66 0f 84 ?? ?? 00 00 } //1
		$a_01_2 = {8b 75 08 83 c6 04 83 e9 04 89 f7 ac 34 90 01 01 89 c3 83 e3 07 83 fb 00 75 01 46 aa e2 ef } //1
		$a_01_3 = {bb 01 00 00 00 3b fb 7c 53 8b c3 b9 05 00 00 00 99 f7 f9 85 d2 75 21 b8 0c 00 00 00 e8 } //1
	condition:
		((#a_0b_0  & 1)*1+(#a_0b_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}