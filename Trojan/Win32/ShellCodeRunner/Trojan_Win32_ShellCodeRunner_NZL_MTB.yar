
rule Trojan_Win32_ShellCodeRunner_NZL_MTB{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.NZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 8b 5d f0 88 0c 3a 8b 55 e0 0f b6 0c 02 0f b6 04 3a 03 c8 83 7e ?? 0f 0f b6 c1 8b ce 89 45 ec 76 } //5
		$a_03_1 = {8a 0c 01 32 0c 16 8b 53 ?? 88 4d ff 3b 53 08 74 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}