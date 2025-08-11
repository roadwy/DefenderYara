
rule Trojan_Win64_ShellcodeRunner_SXA_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d0 48 89 45 f8 48 83 7d f8 00 75 07 b8 01 00 00 00 eb 1c 8b 55 ec 48 8b 45 f8 89 10 48 8b 45 f8 48 89 45 f0 48 8b 45 f0 ff d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}