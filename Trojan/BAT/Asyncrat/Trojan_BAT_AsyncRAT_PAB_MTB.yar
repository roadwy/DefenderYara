
rule Trojan_BAT_AsyncRAT_PAB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 08 08 28 ?? ?? ?? 0a 13 09 19 8d ?? ?? ?? 01 13 0b 11 0b 16 11 08 a2 11 0b 17 7e ?? ?? ?? 0a a2 11 0b 18 09 a2 11 0b 13 0a 11 09 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 13 0c 11 0c 16 11 05 a2 11 0c 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 13 0d 11 0d 16 11 07 a2 11 0d 28 ?? ?? ?? 0a 20 00 01 00 00 14 14 11 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 26 17 28 ?? ?? ?? 0a 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}