
rule Trojan_Win64_ShellcodeRunner_KLX_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KLX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 14 99 48 ff c3 48 3b d8 72 f5 48 8b 9c 24 b8 00 00 00 48 8d 04 85 00 00 00 00 49 3b c1 73 0b 30 14 01 48 ff c0 49 3b c1 72 f5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}