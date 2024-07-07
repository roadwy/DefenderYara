
rule Backdoor_BAT_Nanocore_ABBO_MTB{
	meta:
		description = "Backdoor:BAT/Nanocore.ABBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {07 6f 7b 00 00 0a 28 a0 00 00 06 28 a7 00 00 06 28 d1 00 00 06 17 9a 80 39 00 00 04 11 07 20 52 7d c7 ae 5a 20 5f 7b 2d b9 61 38 db fd ff ff } //2
		$a_01_1 = {48 79 76 65 73 } //1 Hyves
		$a_01_2 = {43 68 65 61 74 4d 65 6e 75 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CheatMenu.Properties.Resources.resources
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}