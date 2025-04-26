
rule Backdoor_BAT_Remcos_SOK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 14 07 11 14 91 11 04 11 15 95 61 d2 9c 00 11 14 17 58 13 14 11 14 07 8e 69 fe 04 13 18 11 18 3a 66 ff ff ff } //2
		$a_81_1 = {43 53 35 30 5f 4d 65 64 69 63 61 6c 5f 41 70 70 2e 57 65 6c 63 6f 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //2 CS50_Medical_App.Welcome.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}