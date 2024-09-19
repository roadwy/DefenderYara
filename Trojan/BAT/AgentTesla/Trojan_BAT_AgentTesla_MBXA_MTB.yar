
rule Trojan_BAT_AgentTesla_MBXA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 41 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 00 00 0d 43 00 6c 00 69 00 65 00 6e } //1
		$a_01_1 = {50 69 7a 7a 61 4f 72 64 65 72 52 65 63 65 69 70 74 2e 46 69 6c 65 73 2e 44 65 66 } //1 PizzaOrderReceipt.Files.Def
		$a_01_2 = {43 6c 69 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Client.Properties
		$a_01_3 = {55 72 6c 54 6f 6b 65 6e 44 65 63 6f 64 65 } //1 UrlTokenDecode
		$a_01_4 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}