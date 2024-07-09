
rule Trojan_WinNT_Padstew_A{
	meta:
		description = "Trojan:WinNT/Padstew.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d ec 8b 55 f8 8b 45 f4 8b 00 89 04 8a 0f 20 c0 } //1
		$a_03_1 = {b9 1b 00 00 00 c7 44 88 34 ?? ?? 40 00 49 75 f5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}