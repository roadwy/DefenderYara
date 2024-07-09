
rule Trojan_BAT_AsyncRAT_PSWK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PSWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 26 00 00 04 28 ?? 00 00 0a 1e 8d 49 00 00 01 25 d0 3e 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 72 2c 0c 00 70 02 72 32 0c 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 80 25 00 00 04 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}