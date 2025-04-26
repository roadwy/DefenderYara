
rule Trojan_BAT_AsyncRAT_RDY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 94 13 0a 11 07 11 08 03 11 08 91 11 0a 61 28 ?? ?? ?? ?? 9c 11 08 17 58 13 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}