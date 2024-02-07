
rule Trojan_Win32_QakBot_BM_MTB{
	meta:
		description = "Trojan:Win32/QakBot.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 33 18 89 5d a0 } //03 00 
		$a_01_1 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 a8 8b 55 d8 01 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_QakBot_BM_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6e 73 74 61 6c 6c } //01 00  DllInstall
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_2 = {48 69 65 66 70 6c 6e 42 61 79 64 6f 66 } //00 00  HiefplnBaydof
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_QakBot_BM_MTB_3{
	meta:
		description = "Trojan:Win32/QakBot.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 65 6e 61 6d 6f 75 72 6d 65 6e 74 } //01 00  coenamourment
		$a_01_1 = {67 69 61 6e 74 68 6f 6f 64 } //01 00  gianthood
		$a_01_2 = {68 6f 61 78 65 72 } //01 00  hoaxer
		$a_01_3 = {73 75 70 65 72 63 61 72 67 6f } //01 00  supercargo
		$a_01_4 = {70 73 6f 72 69 61 74 69 66 6f 72 6d } //01 00  psoriatiform
		$a_01_5 = {75 6e 65 78 70 6c 69 63 69 74 6e 65 73 73 } //01 00  unexplicitness
		$a_01_6 = {6d 65 63 6f 6e 6f 70 68 61 67 69 73 6d } //01 00  meconophagism
		$a_01_7 = {74 68 75 72 69 66 65 72 } //00 00  thurifer
	condition:
		any of ($a_*)
 
}