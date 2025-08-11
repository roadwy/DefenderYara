
rule Trojan_Win32_ShellCode_EAYU_MTB{
	meta:
		description = "Trojan:Win32/ShellCode.EAYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 10 23 fa 0b f7 0b ce 8b 45 f8 03 45 fc 88 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}