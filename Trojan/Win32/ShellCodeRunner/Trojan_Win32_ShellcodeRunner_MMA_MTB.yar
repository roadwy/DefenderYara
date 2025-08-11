
rule Trojan_Win32_ShellcodeRunner_MMA_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.MMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 5b 0f b6 34 10 33 f1 8a 8e ?? ?? ?? ?? 30 4c 07 40 0f b6 4c 07 40 40 83 f8 10 7c } //5
		$a_03_1 = {8b 55 14 8b c8 83 e1 ?? 8a 0c 11 30 0c 18 40 3b 45 1c 7c } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}