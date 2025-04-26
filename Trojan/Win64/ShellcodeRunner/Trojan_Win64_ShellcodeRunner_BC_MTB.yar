
rule Trojan_Win64_ShellcodeRunner_BC_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 c7 c0 60 00 00 00 65 48 8b 18 48 c7 c0 18 00 00 00 48 8b 1c 03 48 c7 c0 20 00 00 00 48 8b 1c 03 49 89 dc 48 8b 53 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}