
rule Trojan_BAT_Tedy_PSMJ_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 72 01 00 00 70 28 03 00 00 06 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 04 2b 30 11 04 6f ?? ?? ?? 0a 74 1e 00 00 01 72 63 00 00 70 28 03 00 00 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 1b 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}