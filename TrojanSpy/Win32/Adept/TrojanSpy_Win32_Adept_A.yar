
rule TrojanSpy_Win32_Adept_A{
	meta:
		description = "TrojanSpy:Win32/Adept.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 fb 0a 74 15 80 fb 0d 74 10 8b c6 99 f7 7d ?? 8b 45 ?? 8a 04 02 32 c3 88 01 } //2
		$a_03_1 = {74 37 66 81 7d 10 bb 01 74 07 68 ?? ?? ?? ?? eb 05 } //1
		$a_01_2 = {5f 4f 5f 4b 5f } //1 _O_K_
		$a_01_3 = {53 74 61 72 74 20 41 75 64 69 74 } //1 Start Audit
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}