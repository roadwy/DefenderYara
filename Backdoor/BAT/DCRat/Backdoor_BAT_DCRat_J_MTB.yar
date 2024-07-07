
rule Backdoor_BAT_DCRat_J_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 ff a3 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 24 01 00 00 af 03 00 00 04 0c 00 00 15 1c } //2
		$a_01_1 = {44 00 61 00 72 00 6b 00 43 00 72 00 79 00 73 00 74 00 61 00 6c 00 20 00 52 00 41 00 54 00 } //2 DarkCrystal RAT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}