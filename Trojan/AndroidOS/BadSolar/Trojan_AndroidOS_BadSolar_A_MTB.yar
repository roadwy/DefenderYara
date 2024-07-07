
rule Trojan_AndroidOS_BadSolar_A_MTB{
	meta:
		description = "Trojan:AndroidOS/BadSolar.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {79 68 6e 72 66 76 } //1 yhnrfv
		$a_00_1 = {4c 63 6f 6d 2f 53 6f 6c 41 52 43 53 2f 53 6f 6c 43 6c 69 65 6e 74 2f 43 6c 69 65 6e 74 } //1 Lcom/SolARCS/SolClient/Client
		$a_00_2 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_00_3 = {43 6f 6d 6d 61 6e 64 45 78 65 63 75 74 65 } //1 CommandExecute
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}