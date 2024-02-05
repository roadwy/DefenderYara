
rule Worm_Win32_Zazorex_D{
	meta:
		description = "Worm:Win32/Zazorex.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 61 6a 61 78 2f 63 68 61 74 2f 73 65 6e 64 2e 70 68 70 3f 5f 5f 61 3d 31 } //01 00 
		$a_03_1 = {50 ff 75 f8 ff 55 f0 8b 45 fc ff 70 04 8b 45 0c 68 90 01 04 ff 30 e8 90 01 04 83 c4 24 ff 75 fc ff 55 f4 59 ff 75 f8 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}