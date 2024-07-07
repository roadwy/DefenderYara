
rule Trojan_BAT_QuasarRAT_S_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 1f 0b 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 73 90 01 01 01 00 0a 0c 7e 90 01 01 03 00 04 07 7e 90 01 01 03 00 04 08 1f 20 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}