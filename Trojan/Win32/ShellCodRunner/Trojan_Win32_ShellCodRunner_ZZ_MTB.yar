
rule Trojan_Win32_ShellCodRunner_ZZ_MTB{
	meta:
		description = "Trojan:Win32/ShellCodRunner.ZZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 89 c4 48 89 c5 66 0f ef c0 48 01 be 80 20 00 00 49 c1 fc 15 0f 29 40 10 48 c1 fd 0c 48 89 78 08 48 c7 00 01 00 00 00 41 0f b6 c4 4c 8d 2c c6 49 8b 95 a8 20 00 00 48 85 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}