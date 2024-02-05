
rule PWS_Win32_CoinStealer_H_bit{
	meta:
		description = "PWS:Win32/CoinStealer.H!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 03 8b 7d 90 01 01 8b 4d 90 01 01 8b 45 90 01 01 03 c7 8d 1c 31 03 9d 90 01 04 83 3d 90 01 05 89 45 90 01 01 8a 00 75 25 6a 90 01 01 59 2b 4d 90 01 01 6a 90 01 01 5a 2b 95 90 01 04 0f af ca 0f af cf 0f af 4d 90 01 01 0f af ce 0f af 8d 90 01 04 8b f1 90 00 } //01 00 
		$a_03_1 = {75 1c 8b 85 90 01 04 03 fe 03 c6 0f af f8 8b 45 90 01 01 83 c0 90 01 01 0f af f8 0f af fe 01 7d 90 00 } //01 00 
		$a_03_2 = {02 c1 04 39 88 85 90 01 04 8d 85 90 01 04 c6 85 90 01 04 ff c6 85 90 01 04 53 c6 85 90 01 04 4d c6 85 90 01 04 42 c6 85 90 01 04 75 c6 85 90 01 04 18 c6 85 90 01 04 01 c6 85 90 01 04 20 c6 85 90 01 04 28 c6 85 90 01 04 04 c6 85 90 01 04 ff c6 85 90 01 04 07 c6 85 90 01 04 10 c6 85 90 01 04 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}