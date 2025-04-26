
rule TrojanSpy_Win32_Seclining_gen_C{
	meta:
		description = "TrojanSpy:Win32/Seclining.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 8a 45 ff c0 c8 02 88 45 ff 8a 45 ff 42 81 fa 00 92 00 00 88 01 7c da } //1
		$a_00_1 = {78 6b 6c 30 32 00 } //1 歸ぬ2
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}