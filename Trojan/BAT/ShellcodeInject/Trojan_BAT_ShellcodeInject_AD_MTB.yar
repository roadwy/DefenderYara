
rule Trojan_BAT_ShellcodeInject_AD_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeInject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 8d 1c 00 00 01 0a 16 0b 2b 15 00 06 07 03 07 91 04 07 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0d 09 2d e1 } //6
		$a_03_1 = {41 70 70 5f 57 65 62 5f 90 04 08 06 61 2d 7a 30 2d 39 2e 64 6c 6c } //2
		$a_81_2 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //1 notepad.exe
		$a_81_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*6+(#a_03_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=10
 
}