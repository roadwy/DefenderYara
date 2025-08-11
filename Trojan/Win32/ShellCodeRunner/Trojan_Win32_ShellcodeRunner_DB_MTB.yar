
rule Trojan_Win32_ShellcodeRunner_DB_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 8b 55 f0 8b 45 08 01 d0 31 cb 89 da 88 10 83 45 f0 01 83 55 f4 00 8b 45 f0 8b 55 f4 3b 45 e0 89 d0 1b 45 e4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}