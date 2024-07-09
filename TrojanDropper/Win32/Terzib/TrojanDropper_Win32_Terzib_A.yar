
rule TrojanDropper_Win32_Terzib_A{
	meta:
		description = "TrojanDropper:Win32/Terzib.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 b1 85 8a ?? ?? ?? 40 00 32 d1 88 ?? ?? ?? 40 00 40 3d 80 54 01 00 72 ea 56 68 80 54 01 00 6a 01 68 ?? ?? 40 00 e8 ?? 00 00 00 } //1
		$a_01_1 = {00 77 62 00 00 25 73 5c 73 6d 63 67 75 69 2e 65 78 65 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}