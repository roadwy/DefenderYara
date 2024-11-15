
rule Trojan_Win32_ShellcodeInject_AMZ_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeInject.AMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 f7 74 24 2c 8b 44 24 18 0f be 0c 11 31 c8 88 c2 8b 84 24 44 01 00 00 8b 4c 24 28 88 14 08 8b 44 24 28 83 c0 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}