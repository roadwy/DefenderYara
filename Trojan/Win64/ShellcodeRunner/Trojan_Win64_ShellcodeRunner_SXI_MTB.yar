
rule Trojan_Win64_ShellcodeRunner_SXI_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 7c 24 5c 10 7c ?? eb ?? 48 8b 44 24 78 48 63 4c 24 5c 8a 04 08 48 63 4c 24 5c 88 84 0c 80 00 00 00 8b 44 24 5c 83 c0 01 89 44 24 5c eb } //30
		$a_03_1 = {48 83 c2 10 48 8b 0d ?? ?? ?? ?? 4c 8d 5c 24 60 45 31 c9 4c 89 54 24 20 c7 44 24 28 10 00 00 00 48 89 44 24 30 c7 44 24 38 80 00 00 00 4c 89 5c 24 40 c7 44 24 48 01 00 00 00 e8 ?? ?? ?? ?? 48 8b 44 24 68 8b 4c 24 60 c6 04 08 00 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}