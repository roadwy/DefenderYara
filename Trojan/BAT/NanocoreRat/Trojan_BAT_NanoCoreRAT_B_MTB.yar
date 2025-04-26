
rule Trojan_BAT_NanoCoreRAT_B_MTB{
	meta:
		description = "Trojan:BAT/NanoCoreRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 5d 13 09 02 11 08 8f ?? 00 00 01 25 47 07 11 09 91 61 d2 52 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}