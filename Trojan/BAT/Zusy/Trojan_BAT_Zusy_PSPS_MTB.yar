
rule Trojan_BAT_Zusy_PSPS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 7b 06 00 00 04 04 6f ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 25 07 6f ?? ?? ?? 0a 72 43 01 00 70 6f 51 00 00 0a 6f 52 00 00 0a 13 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}