
rule Trojan_BAT_XWorm_AYB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 00 69 00 74 00 62 00 75 00 63 00 6b 00 65 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 6d 00 63 00 61 00 66 00 65 00 65 00 2d 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 68 00 6f 00 64 00 68 00 30 00 30 00 39 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 62 00 69 00 6e 00 } //2 bitbucket.org/mcafee-online/hodh009/downloads/loader.bin
		$a_01_1 = {43 6f 6e 73 6f 6c 65 41 70 70 31 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 43 6f 6e 73 6f 6c 65 41 70 70 31 2e 70 64 62 } //1 ConsoleApp1\obj\Release\ConsoleApp1.pdb
		$a_00_2 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //1 Debugger detected
		$a_00_3 = {53 00 61 00 6e 00 64 00 62 00 6f 00 78 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //1 Sandbox detected
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}