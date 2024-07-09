
rule TrojanSpy_Win32_Alinaos_A{
	meta:
		description = "TrojanSpy:Win32/Alinaos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 64 6c 65 78 3d 00 } //1
		$a_01_1 = {5c 5c 2e 5c 70 69 70 65 5c 61 6c 69 6e 61 00 } //1
		$a_03_2 = {f7 e1 c1 ea 02 8d 04 d2 03 c0 8b d1 2b d0 8a 44 15 ?? 30 04 31 41 3b cf 72 e1 90 09 05 00 b8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}