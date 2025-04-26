
rule Trojan_Win32_ShellcodeLoader_A_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 45 f0 48 8b 45 f0 48 81 c4 d0 00 00 00 5d c3 55 48 81 ec 60 02 00 00 48 8d ac 24 80 00 00 00 48 89 8d f0 01 00 00 48 89 95 f8 01 00 00 4c 89 85 00 02 00 00 4c 89 8d 08 02 00 00 48 c7 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}