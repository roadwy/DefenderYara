
rule Trojan_Win64_ShellLoader_SXB_MTB{
	meta:
		description = "Trojan:Win64/ShellLoader.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba 00 00 10 00 33 c9 41 b9 40 00 00 00 41 b8 00 10 00 00 ff d0 48 8b d8 48 89 44 24 48 4c 89 7c 24 20 45 33 c9 41 b8 00 00 10 00 48 8b d0 48 8b ce ff 15 } //30
		$a_01_1 = {b9 48 00 00 00 8b 04 39 ba 38 00 00 00 48 8d 1c 17 a8 01 75 2c 83 c8 01 89 04 39 } //10
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*10) >=40
 
}