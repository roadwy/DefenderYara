
rule Backdoor_BAT_Malpos_A{
	meta:
		description = "Backdoor:BAT/Malpos.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {00 44 00 45 00 56 00 2d 00 50 00 4f 00 49 00 4e 00 54 90 19 01 09 30 2d 39 41 2d 5a 61 2d 7a 90 09 01 00 90 19 01 09 30 2d 39 41 2d 5a 61 2d 7a } //1
		$a_02_1 = {44 45 56 2d 50 4f 49 4e 54 90 19 01 09 30 2d 39 41 2d 5a 61 2d 7a 90 09 01 00 90 19 01 09 30 2d 39 41 2d 5a 61 2d 7a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}