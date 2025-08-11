
rule Trojan_Win64_ShellcodeRunner_PSG_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.PSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 b7 48 8b 85 d8 07 00 00 48 89 85 c8 07 00 00 48 8b 85 c8 07 00 00 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}