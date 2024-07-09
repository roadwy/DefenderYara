
rule Ransom_Win32_LockScreen_H{
	meta:
		description = "Ransom:Win32/LockScreen.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 ab ad 2d ?? ?? ?? ?? 03 c2 ab ad } //1
		$a_01_1 = {74 13 34 0e 66 0f b6 c0 42 66 89 01 8a 02 83 c1 02 3c 0e 75 ed } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Ransom_Win32_LockScreen_H_2{
	meta:
		description = "Ransom:Win32/LockScreen.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 ab ad 2d ?? ?? ?? ?? 03 c2 ab ad } //1
		$a_03_1 = {77 03 80 c1 ?? 0f be c9 69 c9 ?? 00 00 00 03 c8 c1 c1 ?? 8b c1 8a 0a 84 c9 75 dc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_LockScreen_H_3{
	meta:
		description = "Ransom:Win32/LockScreen.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ab ad c1 c8 ?? ab ad c1 (c0|c8) ?? ab ad } //1
		$a_03_1 = {8b 1c 0a 3b 19 75 ?? 83 ee 04 83 c1 04 83 fe 04 73 ee } //1
		$a_03_2 = {8b 31 3b 30 75 ?? 83 ea 04 83 c0 04 83 c1 04 83 fa 04 73 ec } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}