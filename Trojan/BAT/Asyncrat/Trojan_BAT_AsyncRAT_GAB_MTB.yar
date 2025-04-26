
rule Trojan_BAT_AsyncRAT_GAB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 72 ?? 01 00 70 6f ?? 00 00 0a 0b 07 72 ?? 02 00 70 72 ?? 02 00 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 13 05 11 05 16 1f 2c 9d 11 05 6f ?? 00 00 0a 17 9a 0c 08 0a de 1e de 1c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}