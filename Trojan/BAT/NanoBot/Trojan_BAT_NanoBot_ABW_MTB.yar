
rule Trojan_BAT_NanoBot_ABW_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.ABW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 8f 0b 00 00 01 25 47 03 06 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a d2 61 d2 52 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d d5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}