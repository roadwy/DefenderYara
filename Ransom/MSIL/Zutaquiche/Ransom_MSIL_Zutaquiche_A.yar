
rule Ransom_MSIL_Zutaquiche_A{
	meta:
		description = "Ransom:MSIL/Zutaquiche.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {20 49 44 20 2d } // ID -  1
		$a_80_1 = {2e 62 6c 6f 63 6b } //.block  1
		$a_02_2 = {2e 00 64 00 6f 00 63 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 78 00 6c 00 73 00 } //1
		$a_80_3 = {65 6d 61 69 6c 20 79 61 67 61 62 61 62 75 73 68 6b 61 40 79 61 68 6f 6f 2e 63 6f 6d } //email yagababushka@yahoo.com  3
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_80_3  & 1)*3) >=4
 
}