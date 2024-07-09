
rule Backdoor_BAT_DCRat_KAA_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 04 11 0a 02 11 0a 91 03 11 0a 03 6f ?? 00 00 0a 5d 28 ?? 00 00 06 61 d2 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}