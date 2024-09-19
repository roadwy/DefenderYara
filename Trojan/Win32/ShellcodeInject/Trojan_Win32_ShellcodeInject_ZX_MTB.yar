
rule Trojan_Win32_ShellcodeInject_ZX_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeInject.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 34 18 2d 40 3b c7 72 f7 60 ff 95 8c fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}