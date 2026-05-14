
rule Trojan_Win64_Phave_VGY_MTB{
	meta:
		description = "Trojan:Win64/Phave.VGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 83 e2 0f 0f b6 14 11 41 30 14 04 48 83 c0 01 48 39 c7 75 e9 } //2
		$a_01_1 = {89 c2 83 c0 01 41 0f b6 0c 14 41 88 4c 15 00 39 46 54 77 ec } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}