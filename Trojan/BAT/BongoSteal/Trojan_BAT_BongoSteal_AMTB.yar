
rule Trojan_BAT_BongoSteal_AMTB{
	meta:
		description = "Trojan:BAT/BongoSteal!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {42 6f 6e 67 6f 53 74 65 61 6c 2e 56 4d } //BongoSteal.VM  1
		$a_80_1 = {72 65 70 6f 73 5c 42 6f 6e 67 6f 53 74 65 61 6c 5c 42 6f 6e 67 6f 53 74 65 61 6c 5c 6f 62 6a 5c 44 65 62 75 67 5c 42 6f 6e 67 6f 53 74 65 61 6c 2e 70 64 62 } //repos\BongoSteal\BongoSteal\obj\Debug\BongoSteal.pdb  1
		$a_80_2 = {73 61 6c 2e 72 6f 73 65 6e 62 75 72 67 } //sal.rosenburg  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}