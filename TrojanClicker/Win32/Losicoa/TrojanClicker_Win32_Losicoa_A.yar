
rule TrojanClicker_Win32_Losicoa_A{
	meta:
		description = "TrojanClicker:Win32/Losicoa.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {39 5a f8 0f 85 33 02 00 00 68 90 01 01 21 42 00 8d 4c 24 1c e8 8b de 00 00 8b 44 24 18 6a 05 53 50 68 34 21 42 00 68 2c 21 42 00 53 c6 44 24 50 03 ff 15 74 c2 41 00 90 00 } //1
		$a_03_1 = {c7 44 24 18 01 00 00 00 83 f8 06 77 3f ff 24 85 30 46 40 00 68 90 01 02 42 00 eb 28 68 90 01 02 42 00 eb 21 68 90 01 02 42 00 eb 1a 68 90 01 02 42 00 eb 13 68 90 01 02 42 00 eb 0c 68 90 01 02 42 00 eb 05 68 90 01 02 42 00 8d 4c 24 0c e8 4e da 00 00 6a 04 6a 01 51 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}