
rule TrojanSpy_Win32_Wytexu_A{
	meta:
		description = "TrojanSpy:Win32/Wytexu.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 48 6a ff 6a 00 68 b1 00 00 00 50 ff d6 8b 0d ?? ?? 40 00 6a 00 6a 00 68 01 03 00 00 51 ff d6 } //1
		$a_03_1 = {3d 04 18 01 50 74 07 3d 04 18 21 50 75 c7 56 ff 15 ?? ?? 40 00 68 00 01 00 00 8d 4c 24 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}