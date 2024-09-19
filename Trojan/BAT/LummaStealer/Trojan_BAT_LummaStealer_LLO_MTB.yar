
rule Trojan_BAT_LummaStealer_LLO_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.LLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 02 25 17 58 10 00 91 7e 01 00 00 04 02 25 17 58 10 00 91 1e 62 60 7e 01 00 00 04 02 25 17 58 10 00 91 1f 10 62 60 7e 01 00 00 04 02 25 17 58 10 00 91 1f 18 62 60 0c 28 ?? ?? ?? 0a 7e 01 00 00 04 02 08 6f ?? ?? ?? 0a 28 17 00 00 0a a5 01 00 00 1b 0b 11 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}