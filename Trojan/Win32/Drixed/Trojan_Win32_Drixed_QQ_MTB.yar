
rule Trojan_Win32_Drixed_QQ_MTB{
	meta:
		description = "Trojan:Win32/Drixed.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 74 61 72 65 6e 49 72 6d 6f 72 72 61 72 38 39 31 } //LdrGetProcedureAtarenIrmorrar891  03 00 
		$a_80_1 = {7a 63 6f 72 70 72 6e 65 6e 74 63 6f 6d 70 75 74 65 72 72 63 72 65 73 73 5a 61 32 30 31 72 2c 6c 50 77 61 73 } //zcorprnentcomputerrcressZa201r,lPwas  03 00 
		$a_80_2 = {73 72 68 69 64 64 65 6e 38 39 2e 37 35 25 4a 75 6e 65 6e 6f 72 6d 61 6c } //srhidden89.75%Junenormal  03 00 
		$a_80_3 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //FFPGGLBM.pdb  03 00 
		$a_80_4 = {79 66 61 6d 69 6c 79 6a 62 72 6f 77 73 65 72 73 49 72 6f 6e 2c 39 74 6f 33 75 6e 64 65 72 } //yfamilyjbrowsersIron,9to3under  03 00 
		$a_80_5 = {44 65 76 65 6c 6f 70 65 72 5a 38 74 6f 73 70 65 6c 6c 69 6e 67 74 6f 70 2c } //DeveloperZ8tospellingtop,  03 00 
		$a_80_6 = {73 54 68 65 56 6e 6f 53 45 78 70 6c 6f 72 65 72 45 36 64 6f 77 6e 6c 6f 61 64 61 73 } //sTheVnoSExplorerE6downloadas  00 00 
	condition:
		any of ($a_*)
 
}