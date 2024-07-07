
rule Trojan_Win32_Ursnif_PAB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 63 68 6f 6f 6c 70 72 65 73 73 40 40 38 } //1 Schoolpress@@8
		$a_01_1 = {54 72 69 61 6e 67 6c 65 61 72 74 40 40 38 } //1 Triangleart@@8
		$a_01_2 = {42 65 67 69 6e 20 46 75 6e } //1 Begin Fun
		$a_01_3 = {44 61 72 6b 40 40 34 } //1 Dark@@4
		$a_01_4 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_6 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 TerminateProcess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}