
rule Trojan_Win64_ShellcodeRunner_SXF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 1a 9f bf c7 45 ?? de 00 88 f6 c7 45 ?? ?? 8b fa a8 c7 45 ?? 9b 96 8d c3 c7 45 ?? 86 0e 7f d8 c7 45 ?? 97 01 c2 cb } //20
		$a_03_1 = {41 b8 20 00 00 00 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 74 2f 48 c7 44 24 ?? ?? ?? ?? ?? 45 33 c9 4c 8b c3 c7 44 24 ?? ?? ?? ?? ?? 33 d2 33 c9 ff 15 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}