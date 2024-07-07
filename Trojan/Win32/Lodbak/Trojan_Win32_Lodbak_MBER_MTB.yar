
rule Trojan_Win32_Lodbak_MBER_MTB{
	meta:
		description = "Trojan:Win32/Lodbak.MBER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 77 31 36 42 52 57 62 72 77 31 36 4d 52 57 51 } //1 gw16BRWbrw16MRWQ
		$a_81_1 = {62 61 61 6c 71 69 68 78 76 6b 75 62 64 71 6d } //1 baalqihxvkubdqm
		$a_81_2 = {63 7a 64 69 68 6f 66 62 7a 6e 76 66 } //1 czdihofbznvf
		$a_81_3 = {6c 74 67 6b 6b 64 74 75 62 67 69 70 } //1 ltgkkdtubgip
		$a_81_4 = {77 73 6c 65 67 78 75 66 64 6e 70 6f 72 6f } //1 wslegxufdnporo
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}