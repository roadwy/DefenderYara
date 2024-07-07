
rule Trojan_BAT_Tedy_CXQ_MTB{
	meta:
		description = "Trojan:BAT/Tedy.CXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 28 12 00 00 0a 02 6f 90 01 04 6f 90 01 04 00 08 06 6f 90 01 04 00 08 08 6f 90 01 04 08 6f 90 01 04 6f 90 01 04 0d 07 73 90 01 04 13 04 90 00 } //5
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 37 00 38 00 2e 00 32 00 30 00 2e 00 34 00 36 00 2e 00 31 00 34 00 39 00 } //1 http://178.20.46.149
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}