
rule Trojan_Win32_Bobik_GMP_MTB{
	meta:
		description = "Trojan:Win32/Bobik.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8d 45 c4 50 c7 45 ?? 3c 00 00 00 c7 45 ?? 0c 00 00 00 c7 45 ?? a0 f9 40 00 c7 45 ?? e8 e4 40 00 c7 45 ?? 05 00 00 00 ff 15 } //10
		$a_01_1 = {56 57 68 b8 f9 40 00 33 ff ff 15 } //10
		$a_01_2 = {46 49 48 4b 58 49 48 4b } //1 FIHKXIHK
		$a_01_3 = {42 59 54 72 61 73 54 4e 31 73 54 72 61 } //1 BYTrasTN1sTra
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=22
 
}