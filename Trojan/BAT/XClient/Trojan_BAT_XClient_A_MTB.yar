
rule Trojan_BAT_XClient_A_MTB{
	meta:
		description = "Trojan:BAT/XClient.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0b 07 28 90 01 01 00 00 0a 2c 11 07 73 90 01 01 00 00 0a 28 90 01 01 00 00 0a 02 8e 69 6a 2e 07 07 02 28 90 01 01 00 00 0a 07 28 90 00 } //2
		$a_01_1 = {57 68 69 74 65 68 61 74 44 61 74 61 48 4d } //2 WhitehatDataHM
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}