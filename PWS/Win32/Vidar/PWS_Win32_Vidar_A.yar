
rule PWS_Win32_Vidar_A{
	meta:
		description = "PWS:Win32/Vidar.A,SIGNATURE_TYPE_PEHSTR_EXT,ffffff9a 00 ffffff9a 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 65 74 66 75 6c 66 69 6c 6c 65 64 } //01 00  netfulfilled
		$a_00_1 = {6d 6e 70 61 79 6d 65 6e 74 73 } //01 00  mnpayments
		$a_00_2 = {6d 6e 63 61 63 68 65 } //01 00  mncache
		$a_00_3 = {67 6f 76 65 72 6e 61 6e 63 65 } //01 00  governance
		$a_00_4 = {62 61 6e 6c 69 73 74 } //02 00  banlist
		$a_00_5 = {66 65 65 5f 65 73 74 69 6d 61 74 65 73 } //32 00  fee_estimates
		$a_00_6 = {77 61 6c 6c 65 2a 2e 64 61 74 } //32 00  walle*.dat
		$a_00_7 = {63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //32 00  card_number_encrypted FROM credit_cards
		$a_02_8 = {43 61 72 64 3a 90 02 20 4e 61 6d 65 3a 90 02 20 50 61 73 73 77 6f 72 64 3a 90 00 } //00 00 
		$a_00_9 = {5d 04 00 00 e6 f3 03 80 5c 2b 00 00 ee f3 03 80 00 00 01 00 08 00 15 00 ac 21 43 72 65 64 65 6e 74 69 61 6c 41 63 63 65 73 73 21 42 56 00 00 02 40 05 82 70 00 04 00 67 16 00 00 e4 e9 e5 64 38 ad b8 1d 17 aa 2a c7 20 73 23 00 01 20 41 8b 33 55 67 16 00 00 a0 bb 14 db 0e 7e 5e 32 f6 cc 4a af 00 a2 02 } //00 01 
	condition:
		any of ($a_*)
 
}