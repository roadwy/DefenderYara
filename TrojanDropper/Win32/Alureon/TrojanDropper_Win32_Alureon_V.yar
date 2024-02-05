
rule TrojanDropper_Win32_Alureon_V{
	meta:
		description = "TrojanDropper:Win32/Alureon.V,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 78 65 63 44 6f 73 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {37 7a 61 2e 65 78 65 20 78 } //01 00 
		$a_01_2 = {61 31 2e 37 7a 20 2d 61 6f 61 20 2d 6f } //01 00 
		$a_01_3 = {2d 70 6c 6f 6c 6d 69 6c 66 00 } //00 00 
	condition:
		any of ($a_*)
 
}