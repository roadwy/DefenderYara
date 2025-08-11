
rule Trojan_BAT_AsyncRAT_MFA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 73 e6 01 00 0a 0b 07 09 28 ?? 01 00 0a 20 3c 9e 92 2c 28 ?? 04 00 06 28 ?? 01 00 0a 6f ?? 01 00 0a 13 04 73 e4 01 00 0a 0c 08 11 04 17 73 e9 01 00 0a 0a 02 06 6f ?? 01 00 0a 06 6f ?? 01 00 0a 02 6f ?? 01 00 0a de 07 06 6f ?? 00 00 0a dc 03 2d 02 de 10 03 08 6f ?? 01 00 0a de 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}