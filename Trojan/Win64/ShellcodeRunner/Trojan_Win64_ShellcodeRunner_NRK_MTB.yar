
rule Trojan_Win64_ShellcodeRunner_NRK_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 03 f1 48 8b cb 48 33 ce 8b d0 41 0f b6 54 15 10 48 c1 c1 11 48 c1 e9 38 0f b6 c9 33 ca 0f b6 c9 } //1
		$a_01_1 = {c1 e1 04 0b c8 43 88 4c 25 10 41 ff c4 45 3b e7 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}