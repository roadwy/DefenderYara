
rule Worm_Win32_Autorun_ACU{
	meta:
		description = "Worm:Win32/Autorun.ACU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {fe 45 f7 80 7d f7 5b 0f 85 90 01 04 33 c0 90 00 } //01 00 
		$a_00_1 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 64 69 73 61 62 6c 65 } //01 00 
		$a_00_2 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00 
		$a_02_3 = {8d 85 b4 fe ff ff 50 8b 45 fc e8 90 01 04 50 e8 90 01 04 89 45 f4 83 7d f4 ff 74 0f c6 45 fb 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}