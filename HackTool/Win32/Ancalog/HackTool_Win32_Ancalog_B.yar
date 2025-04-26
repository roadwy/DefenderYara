
rule HackTool_Win32_Ancalog_B{
	meta:
		description = "HackTool:Win32/Ancalog.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0d 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 6e 63 61 6c 6f 67 2e 77 69 6e 2f 61 75 74 68 2f } //1 http://ancalog.win/auth/
		$a_01_1 = {55 73 65 20 74 68 69 73 20 66 69 6c 65 20 74 6f 20 69 6e 66 65 63 74 20 76 69 63 74 69 6d } //1 Use this file to infect victim
		$a_01_2 = {45 78 70 6c 6f 69 74 20 42 75 69 6c 64 65 72 } //1 Exploit Builder
		$a_01_3 = {25 25 48 41 58 58 25 25 } //1 %%HAXX%%
		$a_01_4 = {2f 62 79 70 61 73 73 2e 64 6c 6c } //1 /bypass.dll
		$a_01_5 = {2f 75 73 65 72 2e 62 69 6e } //1 /user.bin
		$a_01_6 = {2f 68 74 6d 2e 62 69 6e } //1 /htm.bin
		$a_01_7 = {2f 65 78 70 2e 64 6c 6c } //1 /exp.dll
		$a_01_8 = {2f 66 6c 2e 64 6c 6c } //1 /fl.dll
		$a_01_9 = {63 76 65 32 30 31 35 2d 32 35 34 35 62 79 70 61 73 73 2e 64 6f 63 } //1 cve2015-2545bypass.doc
		$a_01_10 = {59 6f 75 72 45 78 70 6c 6f 69 74 2e 70 64 66 } //1 YourExploit.pdf
		$a_01_11 = {59 6f 75 72 53 69 6c 65 6e 74 45 78 70 6c 6f 69 74 2e 64 6f 63 } //1 YourSilentExploit.doc
		$a_01_12 = {59 6f 75 72 4d 61 63 72 6f 45 78 70 6c 6f 69 74 2e 64 6f 63 } //1 YourMacroExploit.doc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=5
 
}