
rule TrojanSpy_Win32_Seclining_gen_C{
	meta:
		description = "TrojanSpy:Win32/Seclining.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 45 ff 8a 45 ff c0 c8 02 88 45 ff 8a 45 ff 42 81 fa 00 92 00 00 88 01 7c da } //01 00 
		$a_00_1 = {78 6b 6c 30 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}