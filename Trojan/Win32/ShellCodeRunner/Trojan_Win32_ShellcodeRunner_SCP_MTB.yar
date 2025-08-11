
rule Trojan_Win32_ShellcodeRunner_SCP_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.SCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 04 69 c0 ?? ?? ?? ?? 29 c1 89 c8 83 c0 64 89 04 24 } //3
		$a_03_1 = {89 d0 69 c0 ?? ?? ?? ?? 29 c1 89 c8 05 ?? ?? ?? ?? 89 04 24 e8 } //2
		$a_01_2 = {25 73 5c 73 79 73 5f 63 68 65 63 6b 5f 25 6c 75 2e 74 6d 70 } //1 %s\sys_check_%lu.tmp
		$a_01_3 = {72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 5f 00 64 00 61 00 74 00 61 00 2e 00 70 00 6e 00 67 00 } //1 resource_data.png
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}