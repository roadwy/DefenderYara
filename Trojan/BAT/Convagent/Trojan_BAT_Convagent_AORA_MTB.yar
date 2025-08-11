
rule Trojan_BAT_Convagent_AORA_MTB{
	meta:
		description = "Trojan:BAT/Convagent.AORA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0b 16 73 ?? 00 00 0a 13 09 20 03 00 00 00 38 ?? ff ff ff 11 0b 11 08 16 1a 6f ?? 00 00 0a 26 20 02 00 00 00 38 ?? ff ff ff 11 08 16 28 ?? 00 00 0a 13 02 20 00 00 00 00 7e ?? 01 00 04 7b ?? 01 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 } //5
		$a_03_1 = {11 09 11 0c 11 05 11 02 11 05 59 6f ?? 00 00 0a 13 06 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}