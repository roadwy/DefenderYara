
rule Trojan_Win32_Gutosver_A{
	meta:
		description = "Trojan:Win32/Gutosver.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e aa c6 44 24 ?? 63 c6 44 24 ?? 6f c7 44 24 20 01 00 00 00 c6 44 24 ?? 6d 0f 85 } //1
		$a_03_1 = {30 40 00 6a 02 68 ?? ?? ?? ?? ff 90 04 01 02 d6 d7 8b ce e8 ?? ?? 00 00 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 54 24 28 8b 15 ?? ?? ?? ?? 89 54 24 2c 8b 15 ?? ?? ?? ?? 89 54 24 30 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}