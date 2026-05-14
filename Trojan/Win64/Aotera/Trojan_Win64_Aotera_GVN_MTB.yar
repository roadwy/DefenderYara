
rule Trojan_Win64_Aotera_GVN_MTB{
	meta:
		description = "Trojan:Win64/Aotera.GVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4f 0c 81 f1 30 00 30 00 8b 47 0e 35 30 00 31 00 0b c8 75 0a } //2
		$a_01_1 = {44 8b 3e 41 8d 57 01 89 16 44 3b 7b 08 0f 83 b8 01 00 00 48 8b 13 41 8b c7 3b 4d 30 0f 83 a9 01 00 00 4c 8b 45 28 44 8b d1 47 0f b7 04 50 66 44 89 04 42 ff c1 3b 4d 20 7c c6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}