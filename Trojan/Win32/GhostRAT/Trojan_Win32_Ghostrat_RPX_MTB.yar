
rule Trojan_Win32_Ghostrat_RPX_MTB{
	meta:
		description = "Trojan:Win32/Ghostrat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b f2 ff d0 99 b9 0a 00 00 00 f7 f9 42 83 ee 00 74 13 83 ee 01 74 0a 83 ee 01 75 0b 0f af fa eb 06 2b fa eb 02 03 fa 83 ad a8 f5 ff ff 01 8b 35 } //1
		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 42 61 73 65 36 34 4c 6f 61 64 65 72 } //1 ShellcodeBase64Loader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}