
rule Trojan_BAT_SpyAgent_CAZ_MTB{
	meta:
		description = "Trojan:BAT/SpyAgent.CAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 2f 02 00 70 02 7b 0e 00 00 04 28 ?? ?? ?? 0a 0a 00 00 73 6d 00 00 0a 0b 00 73 6e 00 00 0a 0c 03 28 ?? ?? ?? 0a 0d 09 73 70 00 00 0a 13 04 11 04 6f ?? ?? ?? 0a 72 83 02 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 11 04 72 97 02 00 70 72 3f 00 00 70 6f ?? ?? ?? 0a 00 07 06 72 a3 02 00 70 02 7b 0f 00 00 04 28 ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}