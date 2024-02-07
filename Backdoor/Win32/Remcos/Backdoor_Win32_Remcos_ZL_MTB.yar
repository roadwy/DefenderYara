
rule Backdoor_Win32_Remcos_ZL_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.ZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f 8a 54 11 90 01 01 32 c2 5a 88 02 ff 06 4b 75 d1 90 09 19 00 8b 16 8d 44 10 90 01 01 50 8b 45 90 01 01 8b 16 8a 44 10 90 01 01 8b 16 2b 15 90 01 04 8b 90 00 } //01 00 
		$a_01_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 4c 00 69 00 62 00 72 00 61 00 72 00 69 00 65 00 73 00 5c 00 74 00 65 00 6d 00 70 00 } //00 00  C:\Users\Public\Libraries\temp
	condition:
		any of ($a_*)
 
}