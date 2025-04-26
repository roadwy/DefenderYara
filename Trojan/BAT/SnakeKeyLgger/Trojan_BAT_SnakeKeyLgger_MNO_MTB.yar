
rule Trojan_BAT_SnakeKeyLgger_MNO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLgger.MNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 9c 06 00 70 38 b2 00 00 00 38 b7 00 00 00 72 ce 06 00 70 38 b3 00 00 00 1e 3a b7 00 00 00 26 38 b7 00 00 00 38 bc 00 00 00 12 02 38 bb 00 00 00 75 4a 00 00 1b 38 bb 00 00 00 16 2d e2 12 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}