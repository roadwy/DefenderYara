
rule Trojan_Win64_ShellcodeLoader_AJZ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.AJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c8 49 f7 e0 48 c1 ea 03 48 8d 04 92 48 89 ca 48 01 c0 48 29 c2 41 0f b6 04 11 30 04 0e 48 83 c1 01 48 81 f9 00 02 00 00 75 d4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}