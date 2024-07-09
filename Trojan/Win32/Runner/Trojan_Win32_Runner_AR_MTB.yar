
rule Trojan_Win32_Runner_AR_MTB{
	meta:
		description = "Trojan:Win32/Runner.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 08 00 00 "
		
	strings :
		$a_80_0 = {73 74 61 72 74 20 6d 73 68 74 61 20 76 62 73 63 72 69 70 74 3a 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 28 22 22 22 43 3a 5c 6b 6c 5c 63 63 63 2e 63 6d 64 22 22 20 68 22 2c 30 29 28 77 69 6e 64 6f 77 2e 63 6c 6f 73 65 29 26 26 65 78 69 74 } //start mshta vbscript:createobject("wscript.shell").run("""C:\kl\ccc.cmd"" h",0)(window.close)&&exit  10
		$a_02_1 = {53 54 41 52 54 20 68 74 74 70 3a 2f 2f 77 77 77 2e [0-09] 2e 74 77 2f [0-06] 2f 3f } //10
		$a_80_2 = {63 3a 5c 6b 6c 5c 63 63 63 2e 63 6d 64 } //c:\kl\ccc.cmd  10
		$a_80_3 = {43 3a 5c 6b 6c 5c 64 64 64 2e 63 6d 64 } //C:\kl\ddd.cmd  10
		$a_80_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 6f 70 79 } //cmd.exe /c copy  1
		$a_80_5 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_6 = {52 65 67 52 65 61 64 } //RegRead  1
		$a_80_7 = {72 65 67 77 72 69 74 65 } //regwrite  1
	condition:
		((#a_80_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=34
 
}