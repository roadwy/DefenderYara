
rule Trojan_Win64_ShellcodeRunner_KGG_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2b d0 0f b6 08 88 0c 02 48 8d 40 01 49 83 e8 01 75 f0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}