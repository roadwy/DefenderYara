
rule Trojan_BAT_Bladabindi_GPC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 6b 2d 6b 72 6f 6e 61 2e 66 75 6e } //01 00  sk-krona.fun
		$a_01_1 = {00 52 65 73 69 7a 65 00 } //01 00  刀獥穩e
		$a_01_2 = {52 65 76 65 72 73 65 00 } //00 00  敒敶獲e
	condition:
		any of ($a_*)
 
}