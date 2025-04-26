
rule Trojan_BAT_Disfa_SAW_MTB{
	meta:
		description = "Trojan:BAT/Disfa.SAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 17 00 00 0a 0a 06 02 6f ?? ?? ?? 0a 6f 19 00 00 0a 0b 12 01 28 1a 00 00 0a 25 6f 1b 00 00 0a 26 6f 1c 00 00 0a 6f 1d 00 00 0a 6f ?? ?? ?? 0a 0c 12 02 28 1f 00 00 0a 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}