
rule TrojanSpy_Win32_Banker_gen_F{
	meta:
		description = "TrojanSpy:Win32/Banker.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 5c 78 fe 33 5d 90 01 01 3b 5d 90 01 01 7f 0b 81 c3 ff 00 00 00 90 00 } //01 00 
		$a_00_1 = {70 00 65 00 64 00 72 00 6f 00 63 00 61 00 63 00 61 00 72 00 6e 00 65 00 69 00 72 00 6f 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}