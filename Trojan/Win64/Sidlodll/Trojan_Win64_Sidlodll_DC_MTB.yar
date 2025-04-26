
rule Trojan_Win64_Sidlodll_DC_MTB{
	meta:
		description = "Trojan:Win64/Sidlodll.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 63 6f 6d 6d 61 6e 64 20 22 25 73 22 } //powershell.exe -windowstyle Hidden -command "%s"  10
		$a_80_1 = {45 78 65 63 75 74 65 53 63 72 69 70 74 } //ExecuteScript  10
		$a_02_2 = {61 00 63 00 6c 00 75 00 69 00 [0-0f] 2e 00 64 00 6c 00 6c 00 } //10
		$a_02_3 = {61 63 6c 75 69 [0-0f] 2e 64 6c 6c } //10
		$a_80_4 = {43 68 69 6c 64 49 74 65 6d 20 56 61 72 69 61 62 6c 65 3a 5f 29 2e 56 61 6c 75 65 2e 4e 61 6d 65 2d 69 6c 69 6b 65 27 44 2a 67 27 7d 29 2e 4e 61 6d 65 29 2e 49 6e 76 6f 6b 65 28 28 49 74 65 6d 20 56 61 72 69 61 62 6c 65 3a 5c 68 29 2e 56 61 6c 75 65 29 } //ChildItem Variable:_).Value.Name-ilike'D*g'}).Name).Invoke((Item Variable:\h).Value)  1
		$a_80_5 = {6d 65 29 2e 49 6e 76 6f 6b 65 28 27 2a 65 2d 2a 70 72 65 73 73 2a 27 2c 31 2c 24 54 52 55 45 29 29 28 56 61 72 69 61 62 6c 65 20 55 33 29 2e 56 61 6c 75 65 2e 28 28 56 61 72 69 61 62 6c 65 20 49 31 36 29 2e 56 61 6c 75 65 29 2e 49 6e 76 6f 6b 65 28 28 47 65 74 2d 56 61 72 69 61 62 6c 65 20 37 20 2d 56 61 6c 75 65 29 29 } //me).Invoke('*e-*press*',1,$TRUE))(Variable U3).Value.((Variable I16).Value).Invoke((Get-Variable 7 -Value))  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_02_2  & 1)*10+(#a_02_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=31
 
}