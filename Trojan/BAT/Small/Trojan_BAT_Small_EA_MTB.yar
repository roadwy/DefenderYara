
rule Trojan_BAT_Small_EA_MTB{
	meta:
		description = "Trojan:BAT/Small.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 f9 01 00 70 0a 73 34 00 00 0a 0b 73 29 00 00 0a 25 72 e9 00 00 70 6f 2a 00 00 0a 00 25 72 a0 03 00 70 06 72 b6 03 00 70 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}