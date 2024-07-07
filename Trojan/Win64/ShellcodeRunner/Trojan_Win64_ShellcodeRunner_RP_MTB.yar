
rule Trojan_Win64_ShellcodeRunner_RP_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 55 48 8d ac 24 90 fd ff ff 48 81 ec 70 03 00 00 41 b8 04 01 00 00 48 8d 55 60 33 c9 ff 15 } //1
		$a_01_1 = {71 00 77 00 65 00 61 00 73 00 64 00 33 00 32 00 31 00 7a 00 78 00 63 00 } //1 qweasd321zxc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}