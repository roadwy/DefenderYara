
rule Trojan_Win32_Small_AN_MTB{
	meta:
		description = "Trojan:Win32/Small.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {64 00 6c 00 2e 00 6b 00 61 00 6e 00 6c 00 69 00 6e 00 6b 00 2e 00 63 00 6e 00 } //1 dl.kanlink.cn
		$a_01_1 = {68 00 61 00 6f 00 7a 00 69 00 70 00 5f 00 74 00 69 00 6e 00 79 00 } //1 haozip_tiny
		$a_01_2 = {43 00 50 00 41 00 64 00 6f 00 77 00 6e 00 } //1 CPAdown
		$a_01_3 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //1 wscript.shell
		$a_01_4 = {63 00 3a 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 } //1 c:\Loader
		$a_01_5 = {73 00 63 00 72 00 69 00 70 00 74 00 69 00 6e 00 67 00 2e 00 66 00 69 00 6c 00 65 00 73 00 79 00 73 00 74 00 65 00 6d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 } //1 scripting.filesystemobject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}