
rule TrojanSpy_Win64_RustyStealer_B{
	meta:
		description = "TrojanSpy:Win64/RustyStealer.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c2 c1 ea 08 34 30 80 f2 02 41 80 f0 c4 45 0f b6 c0 } //1
		$a_01_1 = {49 c1 e0 30 0f b6 d2 48 c1 e2 28 4c 09 c2 0f b6 c0 48 c1 e0 20 48 09 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}