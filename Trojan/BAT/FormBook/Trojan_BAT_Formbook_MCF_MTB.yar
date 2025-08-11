
rule Trojan_BAT_Formbook_MCF_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 61 b4 6f ?? 00 00 0a 08 17 d6 0c 08 07 31 db } //1
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 WindowsApp1.Resources.resource
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}