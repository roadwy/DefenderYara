
rule TrojanSpy_Win32_Enturp_A{
	meta:
		description = "TrojanSpy:Win32/Enturp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a c1 c0 e8 04 c0 e1 04 0a c1 88 02 8a 4c 16 01 42 84 c9 75 eb } //2
		$a_01_1 = {43 6f 6d 41 67 74 2e 64 6c 6c 00 55 6e 48 6f 6f 6b 00 69 6e 73 74 61 6c 6c 68 6f 6f 6b } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}