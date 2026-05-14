
rule Trojan_Win64_Vidar_CL_MTB{
	meta:
		description = "Trojan:Win64/Vidar.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 8d 57 01 44 0f af d7 41 83 e2 01 83 fe ?? 7c } //5
		$a_01_1 = {4c 6f 61 64 65 72 20 54 61 73 6b 73 } //2 Loader Tasks
		$a_01_2 = {47 72 61 62 62 65 72 20 52 75 6c 65 73 } //2 Grabber Rules
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}