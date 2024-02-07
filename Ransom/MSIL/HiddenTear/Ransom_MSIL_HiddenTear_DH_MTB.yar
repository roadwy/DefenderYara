
rule Ransom_MSIL_HiddenTear_DH_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 78 78 78 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4c 61 75 6e 63 68 65 72 5c 4c 61 75 6e 63 68 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 42 59 2e 70 64 62 } //01 00  \xxx\source\repos\Launcher\Launcher\obj\Debug\BY.pdb
		$a_81_1 = {4c 61 75 6e 63 68 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Launcher.Properties.Resources
		$a_81_2 = {2f 66 20 2f 69 6d 20 42 59 2e 65 78 65 } //01 00  /f /im BY.exe
		$a_81_3 = {67 65 74 5f 42 61 62 61 59 61 67 61 } //01 00  get_BabaYaga
		$a_81_4 = {42 61 62 61 59 61 67 61 2e 65 78 65 } //01 00  BabaYaga.exe
		$a_81_5 = {74 61 73 6b 6b 69 6c 6c } //00 00  taskkill
	condition:
		any of ($a_*)
 
}