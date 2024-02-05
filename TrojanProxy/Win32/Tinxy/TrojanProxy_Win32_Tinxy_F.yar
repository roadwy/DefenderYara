
rule TrojanProxy_Win32_Tinxy_F{
	meta:
		description = "TrojanProxy:Win32/Tinxy.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {6a 1e 51 68 98 01 22 00 50 ff 15 } //01 00 
		$a_01_1 = {83 f8 01 89 45 f8 7d 0b 8b c7 47 83 f8 64 7d 03 53 eb dd } //01 00 
		$a_03_2 = {83 c0 ac 56 50 53 ff 15 90 01 04 8b 3d 90 01 04 8d 45 fc 56 50 6a 50 90 00 } //01 00 
		$a_01_3 = {50 4e 50 5f 54 44 49 00 } //00 00 
	condition:
		any of ($a_*)
 
}