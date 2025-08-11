
rule Trojan_Win64_ShellcodeRunner_DEL_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 33 41 0f b6 c0 41 ff c0 2a c1 04 38 41 30 41 ff 41 83 f8 0e 7c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}