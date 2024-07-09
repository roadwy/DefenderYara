
rule Trojan_BAT_AllComeClipper_B_MTB{
	meta:
		description = "Trojan:BAT/AllComeClipper.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 03 8e 69 14 14 17 28 ?? 00 00 06 d6 13 05 11 05 04 5f 13 06 03 11 04 03 8e 69 14 14 17 28 ?? 00 00 06 91 13 07 06 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}