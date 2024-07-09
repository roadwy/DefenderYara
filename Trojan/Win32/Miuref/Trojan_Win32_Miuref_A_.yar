
rule Trojan_Win32_Miuref_A_{
	meta:
		description = "Trojan:Win32/Miuref.A!!Miuref,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 25 73 25 69 2e 25 69 2e 25 69 2e 25 69 2f 00 } //1
		$a_01_1 = {bb 6b 09 14 00 74 34 8a 0c 3a 80 f9 61 7c 0d 80 f9 7a } //1
		$a_03_2 = {c6 06 7b ff 37 8d 46 01 6a ?? 6a ?? 50 e8 ?? ?? ?? ?? c6 46 09 2d 0f b7 47 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}