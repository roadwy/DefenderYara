
rule Trojan_Win64_ShellcodeRunner_MLZ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 10 00 4c 8d 4c 24 20 ba b1 01 00 00 41 0f 11 00 0f 10 48 10 41 0f 11 48 10 0f 10 40 20 41 0f 11 40 20 0f b6 48 ?? 41 88 48 30 41 b8 20 00 00 00 48 8b cb ff 15 8a 1e 00 00 48 8d 0d 13 21 00 00 e8 ?? ?? ?? ?? ff d3 33 c0 48 8b 4c 24 28 48 33 cc e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}