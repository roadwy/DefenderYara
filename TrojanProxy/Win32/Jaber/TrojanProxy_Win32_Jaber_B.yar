
rule TrojanProxy_Win32_Jaber_B{
	meta:
		description = "TrojanProxy:Win32/Jaber.B,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4c 00 41 00 59 00 45 00 52 00 45 00 44 00 20 00 } //0a 00 
		$a_01_1 = {57 53 43 57 72 69 74 65 50 72 6f 76 69 64 65 72 4f 72 64 65 72 } //0a 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 57 69 6e 53 6f 63 6b 32 5c } //0a 00 
		$a_00_3 = {7a 75 70 61 63 68 61 } //00 00 
	condition:
		any of ($a_*)
 
}