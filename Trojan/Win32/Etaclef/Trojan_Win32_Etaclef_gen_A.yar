
rule Trojan_Win32_Etaclef_gen_A{
	meta:
		description = "Trojan:Win32/Etaclef.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {76 07 fe c2 80 c1 ?? 88 08 0f b6 30 2b de 47 84 d2 56 } //2
		$a_01_1 = {45 58 45 5f 53 54 41 52 54 45 52 } //1 EXE_STARTER
		$a_01_2 = {83 e8 37 83 f8 21 7d 03 83 c0 5e 88 04 32 42 3b d1 7c de } //2
		$a_01_3 = {44 4c 4c 5f 53 54 41 52 54 45 52 } //1 DLL_STARTER
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}