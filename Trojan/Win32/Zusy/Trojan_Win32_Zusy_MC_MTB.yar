
rule Trojan_Win32_Zusy_MC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {eb 52 d8 e2 d8 dc d8 d2 d8 c3 d8 de d8 e0 d8 dd d8 e4 8a 13 d8 c5 d8 e9 d8 e7 89 0b d8 c2 d8 d7 d8 e7 d8 c6 d8 d8 d8 ee d8 c9 d8 e5 d8 c8 8a 0b } //10
		$a_01_1 = {41 53 44 46 47 48 2e 44 4c 4c } //10 ASDFGH.DLL
		$a_01_2 = {52 63 72 74 79 76 4a 62 69 6e } //1 RcrtyvJbin
		$a_01_3 = {45 63 74 72 79 76 4b 75 79 62 69 6e } //1 EctryvKuybin
		$a_01_4 = {47 79 76 74 75 62 4b 79 76 62 } //1 GyvtubKyvb
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}