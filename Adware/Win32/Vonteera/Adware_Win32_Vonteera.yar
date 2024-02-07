
rule Adware_Win32_Vonteera{
	meta:
		description = "Adware:Win32/Vonteera,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 6f 6e 74 65 65 72 61 42 48 4f 40 40 } //01 00  VonteeraBHO@@
		$a_01_1 = {76 00 61 00 72 00 20 00 76 00 6f 00 6e 00 74 00 65 00 65 00 72 00 61 00 5f 00 75 00 73 00 65 00 72 00 5f 00 69 00 64 00 3d 00 27 00 25 00 73 00 27 00 } //01 00  var vonteera_user_id='%s'
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 56 00 6f 00 6e 00 74 00 65 00 65 00 72 00 61 00 } //00 00  Software\Vonteera
	condition:
		any of ($a_*)
 
}