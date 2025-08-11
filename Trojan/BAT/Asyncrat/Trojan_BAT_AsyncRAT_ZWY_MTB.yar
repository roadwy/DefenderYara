
rule Trojan_BAT_AsyncRAT_ZWY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ZWY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 17 59 06 09 91 07 61 1f 0d 59 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 e2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}