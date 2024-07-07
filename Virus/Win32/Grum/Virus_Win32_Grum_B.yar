
rule Virus_Win32_Grum_B{
	meta:
		description = "Virus:Win32/Grum.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 00 00 00 00 5b 81 eb 90 01 04 c3 64 a1 30 00 00 00 85 c0 78 0c 8b 40 0c 8b 70 1c ad 8b 40 08 eb 09 8b 40 34 8b 80 b8 00 00 00 c3 55 8b ec 55 53 56 57 8b 7d 0c 8b f7 8b 6d 08 8b 55 3c 8b 54 2a 78 8d 5c 2a 1c ff 73 04 01 2c 24 33 c9 49 ff 34 24 87 34 24 33 d2 ad 03 c5 c1 c2 03 32 10 40 80 38 00 75 f5 41 87 34 24 39 16 75 e5 8b 43 08 03 c5 0f b7 04 48 c1 e0 02 03 03 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}