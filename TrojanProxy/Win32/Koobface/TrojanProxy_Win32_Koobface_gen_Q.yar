
rule TrojanProxy_Win32_Koobface_gen_Q{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 29 c6 45 fc 55 c6 45 fd 0d } //01 00 
		$a_03_1 = {75 11 ff 15 90 01 04 3d e5 03 00 00 0f 85 90 01 04 68 ff 00 00 00 68 30 75 00 00 8d 45 90 01 01 53 50 6a 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}