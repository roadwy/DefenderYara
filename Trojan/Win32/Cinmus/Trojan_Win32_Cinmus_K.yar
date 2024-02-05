
rule Trojan_Win32_Cinmus_K{
	meta:
		description = "Trojan:Win32/Cinmus.K,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 03 00 00 00 c7 84 00 59 e9 01 00 00 00 e9 83 c1 0a 51 c3 ff 35 ff 25 e9 59 } //01 00 
		$a_03_1 = {e8 03 00 00 00 90 01 03 59 e9 01 00 00 00 90 01 01 83 c1 0a 51 c3 90 01 05 59 33 c0 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}