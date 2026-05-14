
rule Trojan_Win64_ShellcodeRunner_NRG_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 c0 41 89 c1 4c 8d 05 ?? ?? ?? ?? 31 c0 4c 89 c9 4c 89 ca } //1
		$a_03_1 = {0f 94 c0 24 01 88 44 24 ?? 8a 44 24 ?? 24 01 48 83 c4 38 } //2
		$a_03_2 = {48 8b 44 24 ?? 8a 4c 24 ?? 32 08 88 08 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=5
 
}