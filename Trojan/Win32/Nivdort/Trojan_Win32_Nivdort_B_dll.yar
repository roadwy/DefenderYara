
rule Trojan_Win32_Nivdort_B_dll{
	meta:
		description = "Trojan:Win32/Nivdort.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 60 ea 00 00 ff 15 ?? ?? 40 00 eb f3 } //1
		$a_01_1 = {57 ff d6 85 c0 74 f0 57 ff d3 85 c0 75 07 6a 03 58 } //1
		$a_01_2 = {48 6f 6f 6b 44 6f 6e 65 00 00 00 00 48 6f 6f 6b 49 6e 69 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}