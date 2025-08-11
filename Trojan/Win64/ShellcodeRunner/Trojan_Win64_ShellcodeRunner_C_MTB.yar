
rule Trojan_Win64_ShellcodeRunner_C_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 07 30 08 48 8d 40 01 48 83 ea 01 75 ?? eb ?? f3 0f 6f 03 f3 0f 6f 0e 0f 57 c8 f3 0f 7f 0b 48 83 c3 ?? 49 83 c6 ?? 48 83 ef ?? 48 83 c5 ?? 0f 11 36 49 83 ef } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}