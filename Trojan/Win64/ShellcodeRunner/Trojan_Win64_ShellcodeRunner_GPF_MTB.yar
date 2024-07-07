
rule Trojan_Win64_ShellcodeRunner_GPF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.GPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 6d 5a 6d 59 7a 4e 44 4d 33 4d 6d 55 7a 4d 54 } //5 ZmZmYzNDM3MmUzMT
	condition:
		((#a_01_0  & 1)*5) >=5
 
}