
rule Trojan_BAT_Lokibot_PTDT_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PTDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 af d0 c9 86 28 ?? 00 00 2b 28 ?? 00 00 06 28 ?? 00 00 06 0a 06 28 ?? 00 00 06 07 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}