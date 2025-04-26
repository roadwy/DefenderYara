
rule Trojan_Win64_ShellcodeRunner_RDA_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 48 63 0c 24 0f be 04 08 48 8b 4c 24 18 48 63 54 24 04 0f be 0c 11 31 c8 88 c2 48 8b 44 24 08 48 63 0c 24 88 14 08 8b 44 24 04 83 c0 01 89 44 24 04 8b 04 24 83 c0 01 89 04 24 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}