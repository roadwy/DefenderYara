
rule Trojan_BAT_Lokibot_ABXV_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ABXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 c1 02 00 70 28 ?? 00 00 06 74 ?? 00 00 1b 0c 08 28 ?? 00 00 06 00 07 08 6f ?? 00 00 0a 00 07 06 72 cd 02 00 70 28 ?? 00 00 06 74 ?? 00 00 1b 6f ?? 00 00 0a 00 07 06 72 d9 02 00 70 28 ?? 00 00 06 74 ?? 00 00 1b 6f ?? 00 00 0a 00 02 28 ?? 00 00 06 00 28 ?? 00 00 06 07 6f ?? 00 00 0a 28 ?? 00 00 06 0d 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}