
rule Trojan_BAT_Lokibot_PSOB_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.PSOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 72 e8 00 00 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 0b 73 ?? ?? ?? 0a 0c 16 0d 16 13 04 2b 31 16 13 04 2b 1e 07 09 11 04 6f ?? ?? ?? 0a 13 06 08 12 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}