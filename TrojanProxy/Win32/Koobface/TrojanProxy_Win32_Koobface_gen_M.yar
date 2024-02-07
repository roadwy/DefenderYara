
rule TrojanProxy_Win32_Koobface_gen_M{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 14 0f 32 54 24 1c 88 11 49 48 75 f3 } //02 00 
		$a_03_1 = {6f 6b 6f 2e 64 6c 6c 90 09 04 00 90 03 04 04 6d 6d 33 32 62 74 77 5f 90 00 } //01 00 
		$a_01_2 = {2f 75 72 6c 3f } //00 00  /url?
	condition:
		any of ($a_*)
 
}