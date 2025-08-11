
rule Trojan_Win64_Havoc_PAGZ_MTB{
	meta:
		description = "Trojan:Win64/Havoc.PAGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 48 83 ec 30 80 ?? ?? ?? ?? ?? 00 48 8d 5c 24 28 74 ?? 49 89 d8 ba 01 00 00 00 b9 01 00 00 00 ff 15 } //3
		$a_01_1 = {45 31 c0 48 8d 54 24 68 4c 8d 4c 24 70 c7 44 24 28 04 00 00 00 48 89 c1 c7 44 24 20 00 30 00 00 e8 } //2
		$a_01_2 = {41 b9 00 96 01 00 49 89 f0 48 c7 44 24 20 00 00 00 00 48 89 c1 48 89 fa e8 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}