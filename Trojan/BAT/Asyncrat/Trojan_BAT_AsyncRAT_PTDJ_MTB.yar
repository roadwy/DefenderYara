
rule Trojan_BAT_AsyncRAT_PTDJ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PTDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 04 00 00 0a 0b 07 72 01 00 00 70 6f 05 00 00 0a 0c 08 28 ?? 00 00 0a 0a 06 14 28 ?? 00 00 0a 2c 56 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}