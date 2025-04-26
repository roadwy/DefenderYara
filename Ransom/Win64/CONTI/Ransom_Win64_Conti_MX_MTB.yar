
rule Ransom_Win64_Conti_MX_MTB{
	meta:
		description = "Ransom:Win64/Conti.MX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 } //1 vssadmin delete shadows
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 wmic shadowcopy delete
		$a_01_3 = {73 79 73 74 65 6d 5f 68 65 61 6c 74 68 2e 65 78 65 } //1 system_health.exe
		$a_01_4 = {43 6c 65 61 72 2d 43 6f 6d 70 75 74 65 72 52 65 73 74 6f 72 65 50 6f 69 6e 74 20 2d 41 6c 6c } //1 Clear-ComputerRestorePoint -All
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}