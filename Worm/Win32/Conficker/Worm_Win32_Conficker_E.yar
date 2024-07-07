
rule Worm_Win32_Conficker_E{
	meta:
		description = "Worm:Win32/Conficker.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 68 02 02 00 00 ff 15 90 01 04 ff 15 90 01 04 6a 1e 99 59 f7 f9 83 c2 05 69 d2 60 ea 00 00 52 ff d7 6a 63 e8 90 16 55 8b ec 6a ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Worm_Win32_Conficker_E_2{
	meta:
		description = "Worm:Win32/Conficker.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d9 07 72 19 75 10 66 83 7d 90 01 02 72 10 75 07 66 83 7d 90 01 02 72 07 e8 90 16 55 8b ec 81 ec 08 01 00 00 a1 90 01 04 33 c5 89 45 fc 68 04 01 00 00 8d 85 f8 fe ff ff 50 6a 00 ff 15 90 01 04 6a 04 6a 00 8d 85 f8 fe ff ff 50 ff 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}