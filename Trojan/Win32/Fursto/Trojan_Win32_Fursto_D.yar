
rule Trojan_Win32_Fursto_D{
	meta:
		description = "Trojan:Win32/Fursto.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {ff d7 eb e4 68 ?? ?? 40 00 56 ff 15 ?? ?? 40 00 3b c3 74 49 53 56 50 6a 03 ff 15 } //1
		$a_02_1 = {ff d6 eb ea 68 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 3b c3 75 06 6a 01 58 5e eb c2 53 53 53 ff d0 6a f1 ff 15 } //1
		$a_02_2 = {ff d3 eb e4 68 ?? ?? 40 00 57 ff 15 ?? ?? 40 00 3b c6 74 49 56 57 50 6a 03 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}