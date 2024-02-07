
rule TrojanProxy_Win32_Koobface_gen_N{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 29 32 54 24 20 88 11 49 48 75 f3 } //01 00 
		$a_01_1 = {63 66 67 6f 72 6d 64 2e 64 6c 6c } //01 00  cfgormd.dll
		$a_03_2 = {6a 04 58 39 45 08 a3 90 01 04 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}