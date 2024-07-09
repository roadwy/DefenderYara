
rule Trojan_Win64_ShellcodeRunner_CK_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 e6 48 c1 ea 07 48 69 c2 ff 00 00 00 48 8b ce 48 2b c8 40 32 f9 40 30 bc 1d ?? ?? 00 00 48 ff c3 48 83 c6 ?? 48 81 fe } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}