
rule Backdoor_Win32_DarkEnergy_A_bit{
	meta:
		description = "Backdoor:Win32/DarkEnergy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2f 50 61 6e 65 6c 2f 63 61 6c 6c 62 61 63 6b 2e 70 68 70 90 02 30 31 38 35 2e 31 37 37 2e 35 39 2e 31 37 39 90 00 } //01 00 
		$a_01_1 = {66 34 63 6b 79 30 75 6b 61 73 70 65 72 73 6b 79 79 6f 75 77 69 6c 6c 6e 65 76 65 72 67 65 74 66 72 33 73 68 73 61 6d 70 6c 65 6f 66 74 68 69 73 62 6c 34 63 6b 65 6e 33 72 67 79 } //01 00 
		$a_03_2 = {6b 61 73 70 65 72 73 6b 79 90 02 10 74 72 65 6e 64 6d 69 63 72 6f 90 02 10 74 72 75 73 74 6c 6f 6f 6b 90 00 } //01 00 
		$a_01_3 = {7d 2c 22 70 6c 75 67 69 6e 5f } //00 00 
	condition:
		any of ($a_*)
 
}