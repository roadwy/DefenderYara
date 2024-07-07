
rule Trojan_BAT_AsyncRAT_NL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 8e 69 33 02 16 0d 08 11 04 07 11 04 91 06 09 93 90 01 05 61 d2 9c 09 17 58 0d 11 04 17 58 13 04 11 04 07 8e 69 32 d5 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_AsyncRAT_NL_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 20 19 00 00 00 38 59 f2 ff ff 00 02 7b 1f 00 00 04 20 93 90 01 03 20 01 00 00 00 63 20 9d 90 01 03 61 7e 47 01 00 04 7b 2e 01 00 04 61 7e ae 03 00 04 90 00 } //1
		$a_03_1 = {20 75 00 00 00 fe 0e 01 00 38 9b fb ff ff 00 02 11 00 20 82 90 01 03 20 ac d2 88 c5 61 20 9c ef 18 25 61 7e 47 90 01 03 7b 7c 01 00 04 61 7e ae 03 00 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}