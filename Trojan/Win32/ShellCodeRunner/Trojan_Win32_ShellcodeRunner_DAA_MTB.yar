
rule Trojan_Win32_ShellcodeRunner_DAA_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8d ac 24 58 fd ff ff 81 ec 28 03 00 00 a1 ?? ?? ?? ?? 89 85 a4 02 00 00 a1 64 99 42 00 85 c0 74 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}