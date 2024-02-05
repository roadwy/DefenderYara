
rule Backdoor_Win32_Simda_K{
	meta:
		description = "Backdoor:Win32/Simda.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 50 00 61 00 74 00 68 00 5c 00 46 00 69 00 6c 00 65 00 5b 00 35 00 5d 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_03_1 = {60 00 10 8d 90 01 02 d8 ff ff 3b 90 01 01 0f 85 90 01 02 00 00 c7 85 90 01 01 d8 ff ff 90 09 0a 00 8d 90 01 02 d8 ff ff 90 01 01 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}