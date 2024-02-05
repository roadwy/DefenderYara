
rule Trojan_Win32_Yektel_F{
	meta:
		description = "Trojan:Win32/Yektel.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 72 65 65 73 63 61 6e 2e 70 68 70 3f 90 02 01 69 64 3d 25 76 61 72 25 2d 90 00 } //01 00 
		$a_01_1 = {50 49 44 77 6d 73 69 64 00 00 03 } //01 00 
		$a_01_2 = {09 62 74 6e 47 6f 6f 67 6c 65 74 03 00 00 01 00 08 62 74 6e 59 61 68 6f 6f } //02 00 
		$a_03_3 = {e8 df fe ff ff 83 7d f0 00 0f 84 e1 00 00 00 0f b6 05 90 09 05 00 b8 01 00 00 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}