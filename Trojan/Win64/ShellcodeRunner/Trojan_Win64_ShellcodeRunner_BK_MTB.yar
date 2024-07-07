
rule Trojan_Win64_ShellcodeRunner_BK_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d1 48 63 c9 44 0f b6 04 08 48 8b 44 24 08 0f b6 4c 24 06 48 c1 e1 02 48 01 c8 0f b6 4c 24 05 0f b6 14 08 44 31 c2 88 14 08 8a 44 24 05 04 01 88 44 24 05 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}