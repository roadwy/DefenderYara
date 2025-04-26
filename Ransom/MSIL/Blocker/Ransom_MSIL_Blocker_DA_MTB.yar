
rule Ransom_MSIL_Blocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/Blocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 6c 61 63 6b 20 48 61 74 20 57 6f 72 6d } //1 Black Hat Worm
		$a_81_1 = {57 30 30 6f 72 6d 53 50 2e 65 78 65 } //1 W00ormSP.exe
		$a_81_2 = {64 64 6f 73 73 74 6f 70 } //1 ddosstop
		$a_81_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //1 SELECT * FROM AntiVirusProduct
		$a_81_4 = {62 6c 61 63 6b 20 68 61 74 } //1 black hat
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Ransom_MSIL_Blocker_DA_MTB_2{
	meta:
		description = "Ransom:MSIL/Blocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {70 6f 30 77 30 65 72 30 73 68 65 30 6c 30 6c } //1 po0w0er0she0l0l
		$a_81_1 = {70 21 6f 21 77 65 21 72 73 21 68 65 21 6c 6c 21 2e 65 21 78 65 } //1 p!o!we!rs!he!ll!.e!xe
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //1 Software\Microsoft\Windows\CurrentVersion\Run\
		$a_81_3 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //1 WindowsFormsApp
		$a_81_4 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}