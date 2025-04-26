
rule TrojanSpy_Win32_Lurk_gen_A{
	meta:
		description = "TrojanSpy:Win32/Lurk.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 8b f0 6a 65 5f 83 fe 69 0f 85 ?? ?? ?? ?? 0f be 42 02 50 e8 } //1
		$a_01_1 = {32 14 0e 47 88 11 41 84 d2 75 e9 8b 45 08 } //1
		$a_01_2 = {74 16 84 c9 75 21 80 78 fe 65 75 1b 80 78 fd 78 75 15 80 78 fc 65 75 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}