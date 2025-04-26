
rule Trojan_Win32_RedLineStealer_DE_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 0c 57 8b 7d 14 8b c1 8b 75 08 33 d2 f7 f7 8a 04 32 30 04 19 41 3b 4d 10 72 } //1
		$a_81_1 = {68 56 41 78 74 79 66 77 79 66 73 77 74 79 64 66 77 } //1 hVAxtyfwyfswtydfw
		$a_81_2 = {67 76 63 67 66 78 72 64 72 74 77 64 77 74 65 79 73 64 67 66 79 75 66 77 34 36 37 33 65 66 64 73 67 79 74 75 } //1 gvcgfxrdrtwdwteysdgfyufw4673efdsgytu
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}