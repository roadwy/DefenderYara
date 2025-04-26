
rule Backdoor_BAT_DCRat_M_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 55 02 00 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 18 00 00 00 02 00 00 00 01 00 00 00 05 } //2
		$a_01_1 = {44 00 61 00 72 00 6b 00 43 00 72 00 79 00 73 00 74 00 61 00 6c 00 20 00 52 00 41 00 54 00 } //2 DarkCrystal RAT
		$a_01_2 = {6c 7a 6d 61 74 } //1 lzmat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}