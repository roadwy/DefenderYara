
rule Worm_WinNT_Lurka_A{
	meta:
		description = "Worm:WinNT/Lurka.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {81 bd c0 fe ff ff 50 45 00 00 74 04 6a 03 eb ed 81 bd c8 fe ff ff 00 72 19 1a 75 04 6a 04 eb dd } //2
		$a_02_1 = {c6 45 f4 9c c6 45 f5 e8 e8 90 01 02 ff ff 53 ff 75 ec ff 75 f0 e8 90 01 02 ff ff 3b c3 74 05 6a 02 90 00 } //2
		$a_02_2 = {89 45 fc eb 3b c7 45 fc 06 00 00 80 eb 32 33 f6 39 35 90 01 02 01 00 74 25 8d 45 e8 50 53 ff 75 30 e8 90 01 02 ff ff 84 c0 74 14 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*1) >=1
 
}