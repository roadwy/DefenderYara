
rule Backdoor_Win32_Bipfam_A{
	meta:
		description = "Backdoor:Win32/Bipfam.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 68 eb 03 00 00 68 e9 03 00 00 e8 90 01 04 83 c4 10 89 45 f0 83 7d f0 ff 75 15 90 00 } //01 00 
		$a_02_1 = {89 d0 c1 e0 03 01 d0 8d 0c 85 00 00 00 00 8b 16 8b 90 01 02 89 44 0a 18 8d 90 01 02 ff 00 eb 90 01 01 8b 90 01 02 c7 40 04 32 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}