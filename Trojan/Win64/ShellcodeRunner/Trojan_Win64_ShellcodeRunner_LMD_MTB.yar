
rule Trojan_Win64_ShellcodeRunner_LMD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.LMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be c9 4d 8d 49 01 33 d1 8b ca d1 ea 41 23 cd f7 d9 81 e1 20 83 b8 ed 33 ca 8b d1 d1 e9 41 23 d5 f7 da } //20
		$a_03_1 = {0f b6 50 05 0f b6 48 04 c1 e2 08 0b d1 41 89 13 e9 ?? ?? ?? ?? 80 f9 e9 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}