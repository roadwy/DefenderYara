
rule Trojan_Win64_ShellCodeRunner_GPKL_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.GPKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 80 74 24 ?? 57 80 74 24 ?? 59 80 74 24 ?? 5b 80 74 24 ?? 5d 80 74 24 ?? 5f 80 74 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}