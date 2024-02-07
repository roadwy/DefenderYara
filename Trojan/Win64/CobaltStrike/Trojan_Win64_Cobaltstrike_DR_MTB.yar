
rule Trojan_Win64_Cobaltstrike_DR_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 4d 61 69 6e } //0a 00  DllMain
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {79 7a 64 67 74 75 79 6d 75 2e 64 6c 6c } //01 00  yzdgtuymu.dll
		$a_81_3 = {62 66 71 6c 76 6b 6b 6a 79 65 74 76 6b 78 } //01 00  bfqlvkkjyetvkx
		$a_81_4 = {63 6a 6e 76 62 69 73 7a 70 79 7a 65 76 6a } //01 00  cjnvbiszpyzevj
		$a_81_5 = {65 62 78 65 74 73 64 6b 61 6e 75 7a 66 71 6c 74 6b } //01 00  ebxetsdkanuzfqltk
		$a_81_6 = {67 6f 73 64 77 7a 6a 6d 6e 64 6d 65 6f 67 75 69 77 } //00 00  gosdwzjmndmeoguiw
	condition:
		any of ($a_*)
 
}