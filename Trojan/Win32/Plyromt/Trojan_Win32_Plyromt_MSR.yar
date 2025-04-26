
rule Trojan_Win32_Plyromt_MSR{
	meta:
		description = "Trojan:Win32/Plyromt!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 6c 61 63 6b 69 65 76 69 72 75 73 2e 63 6f 6d } //1 http://www.blackievirus.com
		$a_01_1 = {77 65 62 2e 73 74 61 74 75 73 3e 32 30 30 20 74 68 65 6e 20 77 73 63 72 69 70 74 2e 71 75 69 74 } //1 web.status>200 then wscript.quit
		$a_01_2 = {57 49 4e 44 4f 57 53 5c 48 45 4c 50 32 2e 56 42 53 } //1 WINDOWS\HELP2.VBS
		$a_01_3 = {73 68 65 6c 6c 2e 72 75 6e 20 66 69 6c 65 6e 61 6d 65 } //1 shell.run filename
		$a_01_4 = {77 65 62 2e 73 65 6e 64 } //1 web.send
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}