
rule Trojan_BAT_Bladabindi_GPC_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 6b 2d 6b 72 6f 6e 61 2e 66 75 6e } //1 sk-krona.fun
		$a_01_1 = {00 52 65 73 69 7a 65 00 } //1 刀獥穩e
		$a_01_2 = {52 65 76 65 72 73 65 00 } //1 敒敶獲e
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}