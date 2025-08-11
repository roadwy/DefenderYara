
rule Backdoor_BAT_Remcos_STK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.STK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 08 18 6f 07 00 00 0a 1f 10 28 08 00 00 0a 6f 09 00 00 0a 08 18 58 0c 08 07 6f 0a 00 00 0a 3f db ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Backdoor_BAT_Remcos_STK_MTB_2{
	meta:
		description = "Backdoor:BAT/Remcos.STK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 6c 69 63 69 6e 67 44 69 63 65 20 4c 4c 43 } //2 SlicingDice LLC
		$a_81_1 = {24 39 64 61 65 66 66 63 61 2d 39 66 38 39 2d 34 65 30 39 2d 39 31 32 39 2d 34 32 34 38 61 66 61 33 35 33 65 61 } //2 $9daeffca-9f89-4e09-9129-4248afa353ea
		$a_81_2 = {53 6c 69 63 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Slicer.Properties.Resources.resources
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}