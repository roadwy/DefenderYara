
rule Trojan_BAT_Purelogstealer_SRT_MTB{
	meta:
		description = "Trojan:BAT/Purelogstealer.SRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 07 6f 11 00 00 0a 6f 12 00 00 0a 06 fe 06 ?? ?? ?? 06 73 13 00 00 0a 28 01 00 00 2b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}