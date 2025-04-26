
rule Trojan_BAT_AgentTesla_MBXH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 41 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 00 00 0d 43 00 6c 00 69 00 65 00 6e 00 74 00 00 1d } //3 AAഀInvokeഀClientᴀ
		$a_01_1 = {50 69 7a 7a 61 4f 72 64 65 72 52 65 63 65 69 70 74 2e 46 69 6c 65 73 2e 44 65 66 } //2 PizzaOrderReceipt.Files.Def
		$a_01_2 = {53 70 6c 69 74 } //1 Split
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}