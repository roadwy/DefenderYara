
rule Trojan_Win64_DllHijack_LRA_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.LRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff c1 0f b6 c9 44 0f b6 44 0d 00 44 00 c2 44 0f b6 ca 46 0f b6 54 0d 00 44 88 54 0d 00 46 88 44 0d 00 44 02 44 0d 00 45 0f b6 c0 46 0f b6 44 05 00 44 30 04 07 48 ff c0 49 39 c3 } //20
		$a_01_1 = {c1 ea 02 48 8d 42 fe c6 45 f8 00 66 c7 45 f6 00 00 41 89 f1 41 c1 e9 14 4c 8d 05 11 fd 01 00 47 0f b6 0c 01 44 88 4d f9 41 89 f1 41 c1 e9 10 41 83 e1 0f 47 0f b6 0c 01 44 88 4d fa 41 89 f1 41 c1 e9 0c } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}