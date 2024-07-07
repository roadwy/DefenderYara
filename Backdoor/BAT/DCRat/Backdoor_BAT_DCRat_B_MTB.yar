
rule Backdoor_BAT_DCRat_B_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 } //2
		$a_01_1 = {20 40 42 0f 00 5e 0b de } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}