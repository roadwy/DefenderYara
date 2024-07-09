
rule Trojan_BAT_Bulz_PTAG_MTB{
	meta:
		description = "Trojan:BAT/Bulz.PTAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 07 00 00 70 28 ?? 00 00 0a 73 07 00 00 0a 72 49 00 00 70 6f 08 00 00 0a 74 01 00 00 1b 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 72 8f 00 00 70 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}