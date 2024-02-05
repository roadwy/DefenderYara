
rule Backdoor_Win32_Hupigon_FP{
	meta:
		description = "Backdoor:Win32/Hupigon.FP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 76 6d 6f 6e 78 70 2e 6b 78 70 } //01 00 
		$a_00_1 = {6b 2d 6d 65 6c 65 6f 6e 2e 65 78 65 } //01 00 
		$a_00_2 = {6b 77 61 74 63 68 75 69 2e 65 78 65 } //01 00 
		$a_00_3 = {ff ff ff ff 04 00 00 00 3a 74 72 79 00 00 00 00 } //01 00 
		$a_00_4 = {ff ff ff ff 05 00 00 00 64 65 6c 20 22 00 00 00 ff ff ff ff 01 00 00 00 22 00 00 00 } //01 00 
		$a_00_5 = {08 00 4d 00 41 00 49 00 4e 00 49 00 43 00 4f 00 4e 00 } //01 00 
		$a_03_6 = {7d 03 46 eb 05 be 01 00 00 00 8b 45 90 01 01 33 db 8a 5c 30 ff 33 5d 90 01 01 3b fb 7c 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}