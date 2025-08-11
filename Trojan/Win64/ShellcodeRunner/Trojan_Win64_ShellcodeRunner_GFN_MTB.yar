
rule Trojan_Win64_ShellcodeRunner_GFN_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.GFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 3a 0f b6 ?? 2a c2 04 32 41 30 00 ff c1 4d 8d 40 01 83 f9 0f 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}