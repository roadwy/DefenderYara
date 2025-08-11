
rule Trojan_BAT_DCRat_ZLU_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ZLU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 20 00 01 00 00 5d 7d 13 00 00 04 02 02 7b 14 00 00 04 02 7b 12 00 00 04 02 7b 13 00 00 04 91 58 20 00 01 00 00 5d 7d 14 00 00 04 02 02 7b 13 00 00 04 02 7b 14 00 00 04 28 ?? 00 00 06 02 7b 12 00 00 04 02 7b 12 00 00 04 02 7b 13 00 00 04 91 02 7b 12 00 00 04 02 7b 14 00 00 04 91 58 20 00 01 00 00 5d 91 0c 06 07 03 07 91 08 61 d2 9c 07 17 58 0b 07 03 8e 69 3f 7b ff ff ff 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}