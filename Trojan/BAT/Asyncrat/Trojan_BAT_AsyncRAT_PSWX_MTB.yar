
rule Trojan_BAT_AsyncRAT_PSWX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PSWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 3e 0a 00 70 28 90 01 01 00 00 0a 0a 06 28 90 01 01 00 00 06 06 28 90 01 01 00 00 0a 2c 0b 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}