
rule Trojan_Win32_Tibs_JB{
	meta:
		description = "Trojan:Win32/Tibs.JB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 25 00 f0 92 8a 02 34 ?? 3c ?? e8 ?? ?? ?? ?? 75 ?? 81 c2 00 10 00 00 } //1
		$a_01_1 = {80 3a 4d 74 08 81 ea 00 10 00 00 eb f3 83 c4 04 56 57 53 55 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}