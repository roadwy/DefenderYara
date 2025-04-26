
rule Trojan_BAT_StormKitty_ASK_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 25 17 03 a2 25 18 72 2f 09 00 70 a2 25 19 04 a2 25 1a 72 5b 09 00 70 a2 25 1b 02 a2 25 1c 72 69 09 00 70 a2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}