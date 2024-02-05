
rule TrojanDropper_Win32_VB_HR{
	meta:
		description = "TrojanDropper:Win32/VB.HR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 6c 73 52 65 67 48 61 6e 64 6c 65 00 90 01 03 4d 6f 52 65 67 44 6c 6c 00 90 01 0b 71 71 4d 73 67 00 90 00 } //01 00 
		$a_00_1 = {2a 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 5c 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 4d 00 65 00 6e 00 75 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 73 00 5c 00 54 00 68 00 6e 00 75 00 64 00 65 00 72 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}