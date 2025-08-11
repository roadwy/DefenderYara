
rule Backdoor_BAT_Remcos_SRK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 11 10 11 05 91 6f f2 00 00 0a 11 05 17 58 13 05 11 05 11 06 fe 04 13 11 11 11 2d e3 } //2
		$a_01_1 = {24 36 34 39 36 30 37 65 34 2d 38 64 33 33 2d 34 32 36 63 2d 62 33 62 61 2d 36 37 34 35 36 30 32 62 39 66 33 62 } //2 $649607e4-8d33-426c-b3ba-6745602b9f3b
		$a_01_2 = {42 6f 6f 6b 5f 4d 67 74 5f 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Book_Mgt_System.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}