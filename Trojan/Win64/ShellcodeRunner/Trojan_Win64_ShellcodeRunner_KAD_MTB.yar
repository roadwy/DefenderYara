
rule Trojan_Win64_ShellcodeRunner_KAD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 89 d0 41 29 c0 41 8d 40 ?? 66 31 01 83 c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}