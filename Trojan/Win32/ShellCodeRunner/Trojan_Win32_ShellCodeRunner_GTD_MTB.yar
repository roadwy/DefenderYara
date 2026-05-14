
rule Trojan_Win32_ShellCodeRunner_GTD_MTB{
	meta:
		description = "Trojan:Win32/ShellCodeRunner.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 8b 0d ?? ?? ?? ?? 51 6a 00 ff 15 } //5
		$a_03_1 = {cc 55 8b ec 83 ec 08 c7 45 fc ?? ?? ?? ?? 8b 45 fc 50 6a 00 6a 00 ff 15 } //5
		$a_01_2 = {4e 59 49 52 4e 57 52 47 } //1 NYIRNWRG
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}