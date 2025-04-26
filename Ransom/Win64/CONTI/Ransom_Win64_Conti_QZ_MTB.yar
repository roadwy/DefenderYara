
rule Ransom_Win64_Conti_QZ_MTB{
	meta:
		description = "Ransom:Win64/Conti.QZ!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //2 vssadmin delete shadows
		$a_01_1 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //2 wmic shadowcopy delete
		$a_01_2 = {43 6c 65 61 72 2d 43 6f 6d 70 75 74 65 72 52 65 73 74 6f 72 65 50 6f 69 6e 74 20 2d 41 6c 6c } //2 Clear-ComputerRestorePoint -All
		$a_01_3 = {73 79 73 74 65 6d 5f 68 65 61 6c 74 68 2e 65 78 65 } //2 system_health.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}