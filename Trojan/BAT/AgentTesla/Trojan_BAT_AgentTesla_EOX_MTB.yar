
rule Trojan_BAT_AgentTesla_EOX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 09 17 da 6f ?? ?? ?? 0a 03 09 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a da 13 04 07 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 09 17 d6 0d } //1
		$a_01_1 = {77 00 77 00 77 00 77 00 77 00 77 00 77 00 77 00 77 00 } //1 wwwwwwwww
		$a_01_2 = {54 00 6f 00 43 00 68 00 61 00 72 00 41 00 72 00 72 00 61 00 79 00 } //1 ToCharArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}