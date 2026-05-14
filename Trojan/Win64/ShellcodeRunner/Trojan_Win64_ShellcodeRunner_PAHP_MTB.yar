
rule Trojan_Win64_ShellcodeRunner_PAHP_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.PAHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 17 48 ff c2 03 c3 69 c8 01 01 00 00 8b d9 c1 eb 06 33 d9 49 3b d0 75 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}