
rule TrojanProxy_Win32_Koobface_gen_J{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 0a 32 44 24 1c 88 01 49 4d 75 f3 } //02 00 
		$a_01_1 = {65 72 6f 6b 6f 73 76 63 2e 64 6c 6c } //01 00 
		$a_01_2 = {2f 75 72 6c 3f } //00 00 
	condition:
		any of ($a_*)
 
}