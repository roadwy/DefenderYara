
rule HackTool_Win32_Ancalog_A{
	meta:
		description = "HackTool:Win32/Ancalog.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6e 63 61 6c 6f 67 20 4d 75 6c 74 69 20 45 78 70 6c 6f 69 74 20 42 75 69 6c 64 65 72 } //1 Ancalog Multi Exploit Builder
		$a_01_1 = {4d 53 20 57 6f 72 64 20 44 6f 63 20 65 78 70 6c 6f 69 74 65 64 20 6d 61 63 72 6f 20 55 53 47 } //1 MS Word Doc exploited macro USG
		$a_01_2 = {4d 53 20 45 78 63 65 6c 20 58 4c 53 20 65 78 70 6c 6f 69 74 65 64 20 6d 61 63 72 6f 20 55 53 47 } //1 MS Excel XLS exploited macro USG
		$a_01_3 = {53 69 6c 65 6e 74 20 65 78 70 6c 6f 69 74 20 6d 65 74 68 6f 64 3a } //1 Silent exploit method:
		$a_01_4 = {52 65 67 75 6c 61 72 20 65 78 70 6c 6f 69 74 20 6d 65 74 68 6f 64 3a } //1 Regular exploit method:
		$a_01_5 = {53 69 6c 65 6e 74 20 44 4f 43 20 45 78 70 6c 6f 69 74 } //1 Silent DOC Exploit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}