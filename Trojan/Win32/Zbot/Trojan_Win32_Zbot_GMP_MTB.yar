
rule Trojan_Win32_Zbot_GMP_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {6e 6d 73 69 65 78 65 63 2e 65 78 65 } //nmsiexec.exe  01 00 
		$a_01_1 = {25 42 4f 54 49 44 25 } //01 00  %BOTID%
		$a_01_2 = {25 42 4f 54 4e 45 54 25 } //01 00  %BOTNET%
		$a_01_3 = {48 54 54 50 2f 31 2e 31 } //01 00  HTTP/1.1
		$a_01_4 = {4f 6c 7e 4f 69 6b 6f 7a 6c 75 57 70 61 77 56 75 77 } //01 00  Ol~OikozluWpawVuw
		$a_01_5 = {73 77 79 59 77 6d 75 72 66 7c 66 6c } //01 00  swyYwmurf|fl
		$a_01_6 = {5f 5f 69 6e 6a 65 63 74 45 6e 74 72 79 46 6f 72 54 68 72 65 61 64 45 6e 74 72 79 40 34 } //00 00  __injectEntryForThreadEntry@4
	condition:
		any of ($a_*)
 
}