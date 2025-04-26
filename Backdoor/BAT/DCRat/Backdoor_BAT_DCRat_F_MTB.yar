
rule Backdoor_BAT_DCRat_F_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 ff b7 3f 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 26 01 00 00 16 01 00 00 7f 05 00 00 2a 0d } //2
		$a_01_1 = {43 6f 6e 66 75 73 65 72 } //2 Confuser
		$a_01_2 = {42 5a 69 70 32 } //2 BZip2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}