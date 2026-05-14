
rule Trojan_Win64_ShellcodeRunner_NRH_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 44 10 10 44 03 c6 41 8b f0 c1 c6 05 33 de ff c2 3b ca } //1
		$a_01_1 = {33 de 81 c6 99 79 82 5a 41 8b cf 0f b6 54 0f 10 8b c3 c1 e8 08 33 d0 44 0f b6 ea 45 88 6c 0e 10 03 de c1 c6 07 41 ff c7 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}