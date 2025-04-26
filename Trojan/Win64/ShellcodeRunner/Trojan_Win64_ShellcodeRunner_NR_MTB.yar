
rule Trojan_Win64_ShellcodeRunner_NR_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {84 00 c6 80 b0 22 00 00 00 83 3d 0d c3 1c 00 00 0f 85 fc 02 00 00 83 b8 70 22 00 00 00 74 14 48 89 44 24 30 e8 74 cf ff ff } //3
		$a_01_1 = {48 8b 4c 24 20 48 8b 51 30 48 8b 9a a0 00 00 00 48 8d 05 b1 ff 21 00 e8 ec 24 fe ff 48 85 c0 0f 95 c1 0f b6 54 24 15 09 d1 88 4c 24 17 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}