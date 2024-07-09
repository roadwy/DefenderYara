
rule Trojan_BAT_Cobaltstrike_PSQO_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.PSQO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 26 00 00 0a 26 28 ?? ?? ?? 0a 03 03 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 72 6f 01 00 70 28 23 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}