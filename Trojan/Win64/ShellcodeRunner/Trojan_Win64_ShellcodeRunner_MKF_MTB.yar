
rule Trojan_Win64_ShellcodeRunner_MKF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c7 01 48 b8 44 88 41 02 88 41 03 49 8b c0 48 c1 e8 10 88 41 04 49 8b c0 } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}
rule Trojan_Win64_ShellcodeRunner_MKF_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 01 0d 20 20 20 20 3d 2e 74 65 78 ?? ?? 41 ff c0 48 ff c2 48 83 c1 28 49 3b d1 } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}