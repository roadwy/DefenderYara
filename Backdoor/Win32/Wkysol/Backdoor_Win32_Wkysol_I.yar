
rule Backdoor_Win32_Wkysol_I{
	meta:
		description = "Backdoor:Win32/Wkysol.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 67 65 74 2e 61 73 70 3f 6e 6d 3d 69 6e 64 65 78 2e 64 61 74 } //01 00 
		$a_03_1 = {8b 87 a0 01 00 00 83 e8 06 74 90 01 01 83 e8 03 74 90 01 01 83 e8 06 74 90 01 01 83 e8 08 74 90 01 01 48 74 90 01 01 83 e8 04 8d 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}