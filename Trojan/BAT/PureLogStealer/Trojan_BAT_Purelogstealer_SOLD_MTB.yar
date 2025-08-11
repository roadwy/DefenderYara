
rule Trojan_BAT_Purelogstealer_SOLD_MTB{
	meta:
		description = "Trojan:BAT/Purelogstealer.SOLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 61 00 00 70 28 0c 00 00 0a 0a 72 bb 00 00 70 28 0c 00 00 0a 0b 28 0d 00 00 0a 0c 08 06 6f 0e 00 00 0a 08 07 6f 0f 00 00 0a 73 10 00 00 0a 0d 09 08 6f 11 00 00 0a 17 73 12 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}