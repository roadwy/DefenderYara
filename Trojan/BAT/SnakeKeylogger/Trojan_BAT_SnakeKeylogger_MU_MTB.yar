
rule Trojan_BAT_SnakeKeylogger_MU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 16 6a 16 6f ?? ?? ?? 0a 26 08 28 ?? ?? ?? 0a 13 07 11 07 72 8b d5 09 70 6f ?? ?? ?? 0a 13 08 18 8d 06 00 00 01 13 09 11 09 16 72 cb d5 09 70 a2 11 09 17 11 05 a2 11 09 13 0a 11 08 72 3f d6 09 70 20 00 01 00 00 14 14 11 0a 6f ?? ?? ?? 0a 26 dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}