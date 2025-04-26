
rule Trojan_BAT_Tedy_PSOY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSOY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 6f 6e 00 00 0a 72 87 0a 00 70 72 9f 00 00 70 6f 6f 00 00 0a 17 8d 40 00 00 01 25 16 1f 2c 9d 6f 70 00 00 0a 0a 20 ff 00 00 00 06 16 9a 28 71 00 00 0a 06 17 9a 28 71 00 00 0a 06 18 9a 28 71 00 00 0a 28 5e 00 00 0a 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}