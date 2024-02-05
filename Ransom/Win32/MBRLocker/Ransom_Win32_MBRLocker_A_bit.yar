
rule Ransom_Win32_MBRLocker_A_bit{
	meta:
		description = "Ransom:Win32/MBRLocker.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 5c 70 68 79 73 69 63 61 6c 64 72 69 76 65 30 } //0a 00 
		$a_01_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 6c 6f 63 6b 65 64 } //03 00 
		$a_01_2 = {77 77 65 31 30 30 } //02 00 
		$a_03_3 = {6a 00 6a 00 6a 00 56 ff 15 90 01 04 6a 00 8d 45 f4 50 68 00 02 00 00 68 90 01 04 56 ff 15 90 01 04 56 ff 15 90 00 } //01 00 
		$a_01_4 = {32 54 05 f4 40 3b c1 7c f7 } //00 00 
		$a_00_5 = {5d 04 00 00 ae a8 03 80 5c 21 00 00 } //af a8 
	condition:
		any of ($a_*)
 
}