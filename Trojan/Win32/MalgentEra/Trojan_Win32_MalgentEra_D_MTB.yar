
rule Trojan_Win32_MalgentEra_D_MTB{
	meta:
		description = "Trojan:Win32/MalgentEra.D!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 c7 7f 86 53 c6 79 ed 57 c7 7f 86 56 c6 68 ed 57 c7 6b ed 56 c7 38 ed 57 c7 39 98 52 c6 74 ed 57 c7 39 98 53 c6 7b ed 57 c7 39 98 54 c6 7a ed 57 c7 6b ed 57 c7 6a ed 57 c7 de 98 57 c6 6a ed 57 c7 de 98 55 c6 6a ed 57 c7 52 69 63 68 6b ed 57 c7 } //1
		$a_01_1 = {98 c3 06 00 a4 c3 06 00 b0 c3 06 00 bc c3 06 00 ca c3 06 00 d8 c3 06 00 f2 c3 06 00 08 c4 06 00 1e c4 06 00 38 c4 06 00 4e c4 06 00 62 c4 06 00 7e c4 06 00 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}