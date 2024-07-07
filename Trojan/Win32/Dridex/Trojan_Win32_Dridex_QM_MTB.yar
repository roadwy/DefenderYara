
rule Trojan_Win32_Dridex_QM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b c1 2b c6 83 c0 21 2b f1 8d 04 41 } //10
		$a_00_1 = {8b ce 2b ca 8b d6 81 e9 35 f8 00 00 } //10
		$a_80_2 = {6d 69 6c 65 5c 4c 69 6e 65 2e 70 64 62 } //mile\Line.pdb  3
		$a_80_3 = {42 6c 6f 6f 64 62 72 6f 61 64 } //Bloodbroad  3
		$a_80_4 = {52 6f 63 6b 6c 69 6e 65 } //Rockline  3
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=29
 
}
rule Trojan_Win32_Dridex_QM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 47 74 6b 65 6d 76 62 } //3 FGtkemvb
		$a_81_1 = {6d 6e 75 69 65 68 64 62 72 77 65 72 } //3 mnuiehdbrwer
		$a_81_2 = {46 70 6f 72 65 6f 6e 69 59 6a 64 65 67 74 65 73 73 } //3 FporeoniYjdegtess
		$a_81_3 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //3 kernel32.Sleep
		$a_81_4 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //3 RTTYEBHUY.pdb
		$a_81_5 = {57 69 6e 53 43 61 72 64 } //3 WinSCard
		$a_81_6 = {4a 64 69 64 62 72 6f 77 73 65 72 } //3 Jdidbrowser
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}