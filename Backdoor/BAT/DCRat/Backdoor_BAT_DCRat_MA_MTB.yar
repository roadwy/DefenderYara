
rule Backdoor_BAT_DCRat_MA_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {a2 0a 02 28 90 01 03 0a 06 16 9a 03 28 90 01 03 0a 6f 90 01 03 0a 7d 90 01 03 04 02 06 18 9a 02 7b 90 01 03 04 73 90 01 03 06 06 17 9a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}