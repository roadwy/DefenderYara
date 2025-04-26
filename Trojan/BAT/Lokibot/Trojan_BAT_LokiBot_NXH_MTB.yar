
rule Trojan_BAT_LokiBot_NXH_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.NXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {56 47 5a 34 35 36 48 45 35 34 45 34 34 38 4b 43 53 35 35 51 39 43 } //1 VGZ456HE54E448KCS55Q9C
		$a_81_1 = {58 43 43 56 56 } //1 XCCVV
		$a_81_2 = {4c 6f 67 53 77 69 74 63 68 } //1 LogSwitch
		$a_81_3 = {70 30 2e 6a 4f } //1 p0.jO
		$a_81_4 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //1 Rfc2898DeriveBytes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}