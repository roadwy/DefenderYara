
rule TrojanProxy_Win32_Virpen_A{
	meta:
		description = "TrojanProxy:Win32/Virpen.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 74 61 73 6b 3d } //01 00 
		$a_01_1 = {13 41 64 64 50 6f 72 74 4e 75 6d 62 65 72 54 6f 48 6f 73 74 } //01 00 
		$a_00_2 = {69 70 76 70 6e 6d 65 2e 72 75 2f 6c 6f 67 73 2f } //01 00 
		$a_01_3 = {68 49 76 45 00 8d 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}