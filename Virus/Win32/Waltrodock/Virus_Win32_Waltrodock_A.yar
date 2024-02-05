
rule Virus_Win32_Waltrodock_A{
	meta:
		description = "Virus:Win32/Waltrodock.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {9c e8 01 00 00 00 90 01 01 83 c4 04 60 e8 14 00 00 00 90 01 05 ff d1 61 9d ff 15 90 01 04 e9 90 01 04 58 e8 e6 ff ff ff 62 64 63 61 70 45 78 33 32 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}