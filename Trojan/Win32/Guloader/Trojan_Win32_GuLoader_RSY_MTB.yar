
rule Trojan_Win32_GuLoader_RSY_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {65 74 68 61 6e 69 6d 20 70 69 67 20 64 6f 6d 73 75 64 73 6b 72 69 66 74 } //1 ethanim pig domsudskrift
		$a_81_1 = {62 6f 6d 62 79 63 69 66 6f 72 6d 20 66 6c 6a 6c 65 72 6e 65 20 73 65 73 71 75 69 64 75 70 6c 65 } //1 bombyciform fljlerne sesquiduple
		$a_81_2 = {66 6f 72 6d 61 61 6c 73 6c 73 20 66 72 75 65 73 20 6d 65 6c 61 6e 69 65 } //1 formaalsls frues melanie
		$a_81_3 = {66 6c 61 64 62 61 72 6d 65 74 } //1 fladbarmet
		$a_81_4 = {69 6e 66 65 61 73 69 62 69 6c 69 74 69 65 73 20 61 71 75 61 64 75 63 74 2e 65 78 65 } //1 infeasibilities aquaduct.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}