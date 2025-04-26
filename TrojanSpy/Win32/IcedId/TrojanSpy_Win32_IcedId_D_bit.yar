
rule TrojanSpy_Win32_IcedId_D_bit{
	meta:
		description = "TrojanSpy:Win32/IcedId.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c7 82 be 03 00 00 83 e8 8b 45 e4 66 c7 80 c0 03 00 00 04 31 8b 4d e4 66 c7 81 c2 03 00 00 37 83 8b 55 e4 66 c7 82 c4 03 00 00 c7 04 8b 45 e4 66 c7 80 c6 03 00 00 85 c0 8b 4d e4 66 c7 81 c8 03 00 00 75 f4 8b 55 e4 8d 4d bc 66 c7 82 ca 03 00 00 c3 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}