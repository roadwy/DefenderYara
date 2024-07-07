
rule Trojan_BAT_KeyLogger_RDG_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 34 32 30 38 32 65 61 2d 33 66 32 63 2d 34 36 37 39 2d 38 61 34 61 2d 66 64 62 33 65 34 64 30 61 66 30 61 } //1 142082ea-3f2c-4679-8a4a-fdb3e4d0af0a
		$a_01_1 = {57 69 6e 44 65 66 } //1 WinDef
		$a_01_2 = {4b 65 79 54 65 73 74 4a 50 } //1 KeyTestJP
		$a_01_3 = {54 65 6c 61 } //1 Tela
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}