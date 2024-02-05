
rule TrojanSpy_Win32_AcridRain_A_bit{
	meta:
		description = "TrojanSpy:Win32/AcridRain.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5f 30 94 0c 90 01 02 00 00 41 3b cf 73 09 8a 94 24 90 01 02 00 00 eb eb 90 00 } //01 00 
		$a_03_1 = {83 f9 0c 73 1d 32 94 0d 90 01 01 ff ff ff 88 94 0d 90 01 01 ff ff ff 41 89 8d 90 01 01 ff ff ff 8a 95 90 01 01 ff ff ff eb de 90 00 } //01 00 
		$a_01_2 = {8b c1 33 d2 6a 0a 59 f7 f1 4f 8b c8 80 c2 30 88 17 85 c9 75 eb } //00 00 
	condition:
		any of ($a_*)
 
}