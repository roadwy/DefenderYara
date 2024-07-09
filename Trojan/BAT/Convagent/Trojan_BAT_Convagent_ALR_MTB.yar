
rule Trojan_BAT_Convagent_ALR_MTB{
	meta:
		description = "Trojan:BAT/Convagent.ALR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 a2 25 17 28 ?? ?? ?? 0a a2 25 18 72 b3 03 00 70 a2 25 19 28 ?? ?? ?? 0a a2 25 1a 72 07 04 00 70 a2 25 1b 28 ?? ?? ?? 0a a2 25 1c 72 43 04 00 70 a2 25 1d 28 ?? ?? ?? 0a a2 25 1e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}