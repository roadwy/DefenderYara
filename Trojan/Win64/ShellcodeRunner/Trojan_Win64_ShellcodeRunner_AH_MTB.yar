
rule Trojan_Win64_ShellcodeRunner_AH_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b f8 48 8b f1 b9 ?? ?? 00 00 f3 a4 41 b9 40 00 00 00 41 b8 00 30 00 00 ba ?? ?? 00 00 33 c9 ff 15 } //2
		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 20 69 73 20 77 72 69 74 74 65 6e 20 74 6f 20 61 6c 6c 6f 63 61 74 65 64 20 6d 65 6d 6f 72 79 21 } //2 Shellcode is written to allocated memory!
		$a_01_2 = {6d 73 66 68 65 20 62 79 68 6c 63 6f 64 68 53 68 65 6c 31 } //1 msfhe byhlcodhShel1
		$a_01_3 = {68 65 58 20 20 68 6c 63 6f 64 68 53 68 65 6c 31 } //1 heX  hlcodhShel1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}