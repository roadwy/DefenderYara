
rule Backdoor_Win32_Bulknet_MA_MTB{
	meta:
		description = "Backdoor:Win32/Bulknet.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 37 88 06 ff d5 8a cb 80 e9 40 30 0e 43 46 81 fb ff 03 00 00 72 } //01 00 
		$a_01_1 = {53 53 6a 03 53 6a 01 68 00 00 00 80 8d 4c 24 2c 51 ff 15 } //01 00 
		$a_01_2 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //01 00 
		$a_01_3 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 57 } //00 00 
	condition:
		any of ($a_*)
 
}