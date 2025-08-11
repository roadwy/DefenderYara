
rule Trojan_Win64_Havoc_PAHA_MTB{
	meta:
		description = "Trojan:Win64/Havoc.PAHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 48 83 ec 40 0f 11 74 24 30 80 3d ?? ?? ?? ?? 00 0f 10 f0 48 8d 5c 24 28 74 1a 49 89 d8 ba 01 00 00 00 b9 01 00 00 00 ff 15 } //2
		$a_01_1 = {45 31 c0 4c 8d 4c 24 40 4c 89 e2 48 89 c1 c7 44 24 28 04 00 00 00 c7 44 24 20 00 30 00 00 ff } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}