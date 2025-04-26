
rule Trojan_Win32_Bulz_CB_MTB{
	meta:
		description = "Trojan:Win32/Bulz.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 63 75 74 65 20 74 68 69 73 20 6d 61 6c 77 61 72 65 3f } //1 execute this malware?
		$a_01_1 = {59 6f 75 20 61 72 65 20 66 75 63 6b 65 64 20 62 79 20 61 2e 65 78 65 } //1 You are fucked by a.exe
		$a_01_2 = {54 68 61 6e 6b 73 20 74 6f 20 4e 61 74 68 61 6e 74 6f 72 20 66 6f 72 20 68 65 6c 70 69 6e 67 20 6d 65 } //1 Thanks to Nathantor for helping me
		$a_01_3 = {65 78 65 63 75 74 65 3f } //1 execute?
		$a_01_4 = {6c 61 73 74 20 77 61 72 6e 69 6e 67 } //1 last warning
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}