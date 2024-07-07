
rule Trojan_Win64_ShellcodeRunner_CCID_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.CCID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 04 00 00 00 00 41 b9 40 00 00 00 41 b8 00 10 00 00 ba 01 00 00 00 33 c9 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}