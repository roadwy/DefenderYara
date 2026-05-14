
rule Trojan_Win64_ShellcodeRunner_MKE_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb 27 5b 53 5f b0 ?? fc ae 75 fd 57 59 53 5e 8a 06 30 07 48 ff c7 48 ff c6 66 81 3f ?? ?? 74 07 80 3e } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}