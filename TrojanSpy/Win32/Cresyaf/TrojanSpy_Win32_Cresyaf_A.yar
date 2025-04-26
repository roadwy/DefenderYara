
rule TrojanSpy_Win32_Cresyaf_A{
	meta:
		description = "TrojanSpy:Win32/Cresyaf.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 fb 11 0f 84 ?? ?? ?? ?? 80 fb 12 0f 84 ?? ?? ?? ?? 80 fb a0 } //1
		$a_01_1 = {5b 42 4f 54 49 44 3a 20 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}