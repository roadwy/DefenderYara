
rule Backdoor_Win32_Hupigon_ZM{
	meta:
		description = "Backdoor:Win32/Hupigon.ZM,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 07 00 "
		
	strings :
		$a_02_0 = {e8 ea f8 ff ff 84 c0 74 21 e8 79 fd ff ff ba 90 09 16 00 75 3e 68 90 01 02 41 00 ba 90 01 02 41 00 b9 01 00 00 00 b8 0a 00 00 00 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 52 65 67 52 75 6e 2e 72 65 67 } //01 00 
		$a_01_2 = {53 65 72 76 69 63 65 44 6c 6c } //01 00 
		$a_01_3 = {2e 64 6c 6c 00 00 00 54 46 4f 52 4d 32 00 } //01 00 
		$a_01_4 = {64 65 6c 20 25 30 00 00 ff } //01 00 
		$a_01_5 = {20 67 6f 74 6f 20 74 72 79 00 } //01 00 
		$a_00_6 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 41 } //00 00 
	condition:
		any of ($a_*)
 
}