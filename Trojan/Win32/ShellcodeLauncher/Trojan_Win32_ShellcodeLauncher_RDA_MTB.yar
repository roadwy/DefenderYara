
rule Trojan_Win32_ShellcodeLauncher_RDA_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeLauncher.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 e0 8b f4 6a 40 68 00 10 00 00 8b 45 ec 50 6a 00 ff 15 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}