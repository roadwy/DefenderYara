
rule Trojan_BAT_CryptInject_PL_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 37 32 33 30 38 42 30 31 2d 41 43 41 41 2d 34 43 33 38 2d 39 35 39 33 2d 34 36 33 35 34 38 43 33 37 34 37 37 } //1 $72308B01-ACAA-4C38-9593-463548C37477
		$a_81_1 = {44 6f 74 6e 65 74 20 6d 6f 6e 6f 70 6f 6c 79 20 65 61 73 79 20 67 61 6d 65 } //1 Dotnet monopoly easy game
		$a_81_2 = {44 6f 74 4e 65 74 50 6f 6c 79 46 6f 72 6d 73 2e 66 72 6d 53 69 6d 70 6c 65 47 75 69 2e 72 65 73 6f 75 72 63 65 73 } //1 DotNetPolyForms.frmSimpleGui.resources
		$a_81_3 = {44 6f 74 4e 65 74 50 6f 6c 79 2e 73 61 66 61 73 64 46 53 41 46 2e 72 65 73 6f 75 72 63 65 73 } //1 DotNetPoly.safasdFSAF.resources
		$a_81_4 = {4d 6f 6e 6f 47 61 6d 65 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 MonoGame.Form1.resources
		$a_81_5 = {44 6f 74 6e 65 74 20 50 6f 6c 79 } //1 Dotnet Poly
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}