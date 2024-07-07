
rule Backdoor_BAT_Bladabindi_B_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 00 2e 00 68 00 74 00 6d 00 } //2 m.htm
		$a_01_1 = {6a 00 75 00 73 00 74 00 6e 00 6f 00 74 00 68 00 69 00 6e 00 67 00 6c 00 65 00 61 00 76 00 65 00 69 00 74 00 } //2 justnothingleaveit
		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 } //2 ConfuserEx
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 } //2 Windows Explorer
		$a_01_4 = {38 37 62 34 33 66 30 31 2d 30 62 35 65 2d 34 39 62 36 2d 38 64 65 34 2d 37 35 36 33 65 38 34 66 64 37 31 65 } //2 87b43f01-0b5e-49b6-8de4-7563e84fd71e
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}