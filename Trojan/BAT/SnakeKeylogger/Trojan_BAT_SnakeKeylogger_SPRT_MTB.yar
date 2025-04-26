
rule Trojan_BAT_SnakeKeylogger_SPRT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 a3 01 00 00 01 0c 73 ?? ?? ?? 0a 0d 09 72 01 00 00 70 28 ?? ?? ?? 0a 72 33 00 00 70 28 ?? ?? ?? 0a 6f 04 00 00 0a 13 04 14 13 05 38 31 00 00 00 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}