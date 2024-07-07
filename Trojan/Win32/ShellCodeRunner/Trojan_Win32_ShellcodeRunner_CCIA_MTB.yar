
rule Trojan_Win32_ShellcodeRunner_CCIA_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.CCIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c0 01 d0 29 c1 89 ca 0f b6 44 15 90 01 01 31 f0 89 c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}