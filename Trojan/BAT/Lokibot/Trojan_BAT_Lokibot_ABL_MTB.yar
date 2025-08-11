
rule Trojan_BAT_Lokibot_ABL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 0d 2b 25 11 0c 11 0d 94 13 0e 00 11 0e 16 fe 04 13 0f 11 0f 2c 0b 72 ?? 01 00 70 73 ?? 00 00 0a 7a 00 11 0d 17 58 13 0d 11 0d 11 0c 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}