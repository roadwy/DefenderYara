
rule Trojan_Win32_Lukicsel_H{
	meta:
		description = "Trojan:Win32/Lukicsel.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 74 06 04 ?? ff 45 ?? 83 7d ?? 0c 75 ef 8d 46 04 8b 00 b2 04 e8 } //2
		$a_03_1 = {7c 12 43 8d 45 ?? e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef } //1
		$a_03_2 = {83 c0 34 03 d8 8d 55 ?? 8b c3 b9 04 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 5d ?? 83 ee 0a 85 f6 72 28 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}