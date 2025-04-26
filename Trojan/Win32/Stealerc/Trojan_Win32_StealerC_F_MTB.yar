
rule Trojan_Win32_StealerC_F_MTB{
	meta:
		description = "Trojan:Win32/StealerC.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 65 77 61 7a 65 73 6f 76 65 73 61 70 6f 76 65 68 61 6b 75 63 75 63 65 74 } //1 dewazesovesapovehakucucet
		$a_01_1 = {62 75 76 75 62 75 66 75 72 75 73 65 70 65 6a 65 6c 69 76 75 6b 69 6c 61 6b 6f 63 6f 74 75 66 65 } //1 buvubufurusepejelivukilakocotufe
		$a_01_2 = {78 65 6c 61 6c 65 64 6f 76 75 74 69 68 65 7a 65 62 75 79 61 78 61 64 65 63 65 74 65 7a 61 76 } //1 xelaledovutihezebuyaxadecetezav
		$a_81_3 = {6c 75 6d 65 6a 61 73 75 72 69 6e 69 73 6f 6d 65 6b 65 70 } //1 lumejasurinisomekep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}