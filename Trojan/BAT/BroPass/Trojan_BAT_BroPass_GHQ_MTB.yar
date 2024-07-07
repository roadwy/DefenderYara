
rule Trojan_BAT_BroPass_GHQ_MTB{
	meta:
		description = "Trojan:BAT/BroPass.GHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 08 6f 20 90 01 02 0a 00 06 07 6f 90 01 03 0a 0d 09 6f 90 01 03 0a 00 09 6f 90 01 03 0a 13 04 11 04 6f 90 01 03 0a 26 00 de 05 90 00 } //10
		$a_80_1 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 36 31 39 36 36 33 36 38 30 31 } //api.telegram.org/bot6196636801  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}