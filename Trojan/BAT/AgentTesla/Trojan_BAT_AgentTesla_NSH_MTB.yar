
rule Trojan_BAT_AgentTesla_NSH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 02 08 91 03 08 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 61 9c 08 17 d6 0c 08 07 31 de } //1
		$a_03_1 = {02 08 95 28 ?? ?? ?? 0a 0d 09 8e 69 17 da 13 04 16 13 05 2b 12 06 08 1a d8 11 05 d6 09 11 05 91 9c 11 05 17 d6 13 05 11 05 11 04 31 e8 08 17 d6 0c 08 07 31 cb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}