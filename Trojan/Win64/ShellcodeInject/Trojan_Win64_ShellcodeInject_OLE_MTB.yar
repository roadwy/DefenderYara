
rule Trojan_Win64_ShellcodeInject_OLE_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.OLE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 79 10 48 8b df } //1
		$a_01_1 = {0f b6 0c 42 88 4c 04 60 48 ff c0 66 44 39 3c 42 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}