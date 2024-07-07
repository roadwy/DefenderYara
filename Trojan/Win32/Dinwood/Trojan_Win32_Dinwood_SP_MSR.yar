
rule Trojan_Win32_Dinwood_SP_MSR{
	meta:
		description = "Trojan:Win32/Dinwood.SP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 66 00 75 00 69 00 65 00 33 00 32 00 2e 00 32 00 69 00 68 00 73 00 66 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 66 00 62 00 74 00 69 00 6d 00 65 00 } //1 hfuie32.2ihsfa.com/api/fbtime
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {5c 46 42 43 6f 6f 6b 69 65 73 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 } //1 \FBCookiesWin32\Release
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}