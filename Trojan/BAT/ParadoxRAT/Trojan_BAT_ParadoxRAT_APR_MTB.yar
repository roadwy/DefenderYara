
rule Trojan_BAT_ParadoxRAT_APR_MTB{
	meta:
		description = "Trojan:BAT/ParadoxRAT.APR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {2c 35 02 7b ?? 00 00 04 06 9a 6f ?? 00 00 0a 2c 0e 02 7b ?? 00 00 04 06 9a 16 6f ?? 00 00 0a 02 7b ?? 00 00 04 06 9a 6f ?? 00 00 0a 02 7b ?? 00 00 04 06 14 a2 2b 05 } //3
		$a_03_1 = {0d 16 0c 2b 65 09 08 9a 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 02 16 28 ?? 00 00 0a 16 33 48 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 6f } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}