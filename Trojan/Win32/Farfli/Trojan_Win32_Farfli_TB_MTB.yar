
rule Trojan_Win32_Farfli_TB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {85 c0 c6 44 24 1c 57 c6 44 24 1d 69 c6 44 24 1e 6e c6 44 24 1f 53 88 4c 24 20 c6 44 24 22 30 c6 44 24 23 5c 88 54 24 24 c6 44 24 25 65 c6 44 24 26 66 c6 44 24 28 75 c6 44 24 29 6c 88 4c 24 2a c6 44 24 2b 00 74 08 } //01 00 
		$a_01_1 = {73 66 77 75 2e 33 33 32 32 2e 6f 72 67 } //01 00  sfwu.3322.org
		$a_01_2 = {63 3a 5c 57 69 6e 64 6f 77 73 5c 42 4a 2e 65 78 65 } //00 00  c:\Windows\BJ.exe
	condition:
		any of ($a_*)
 
}