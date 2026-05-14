
rule Trojan_Win64_ShellcodeRunner_NTB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b8 3f b5 31 5b c4 f3 68 17 48 89 87 e7 ae 03 00 48 b8 91 bf 74 0f 42 5b bb 36 48 89 87 ef ae 03 00 } //2
		$a_01_1 = {48 b8 21 c7 a1 7a 6d f2 16 dc 48 89 87 1f af 03 00 48 b8 0f 01 bb a6 91 48 47 cc 48 89 87 27 af 03 00 48 b8 e2 95 3f 8e e5 40 a5 99 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}