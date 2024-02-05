
rule Trojan_Win32_AnchorBot_SD_MTB{
	meta:
		description = "Trojan:Win32/AnchorBot.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //01 00 
		$a_81_1 = {72 75 6e 63 6f 6d 6d 61 6e 64 28 25 73 29 2c 20 70 69 64 20 30 } //01 00 
		$a_81_2 = {63 72 65 61 74 65 64 20 70 72 6f 63 65 73 73 20 22 25 73 22 2c 20 70 69 64 20 25 69 } //01 00 
		$a_81_3 = {77 68 65 72 65 20 67 75 69 64 3f 20 77 68 6f 20 77 69 6c 6c 20 64 6f 20 69 74 3f } //00 00 
	condition:
		any of ($a_*)
 
}