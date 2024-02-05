
rule TrojanDropper_Win32_VB_EM{
	meta:
		description = "TrojanDropper:Win32/VB.EM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 08 00 00 00 2f 00 2f 00 2f 00 2f 00 00 00 00 00 06 00 00 00 6c 00 6f 00 6c 00 00 00 } //01 00 
		$a_01_1 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 33 00 4d 6f 64 75 6c 65 36 00 6d 64 73 61 61 61 61 61 64 00 00 00 46 6f 72 6d 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}