
rule Virus_Win32_Zorg_B_bit{
	meta:
		description = "Virus:Win32/Zorg.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 2e 65 78 65 20 73 68 61 72 65 20 24 5a 4f 52 47 24 3d } //1 net.exe share $ZORG$=
		$a_00_1 = {33 c0 a3 a0 77 41 00 8d 45 e4 b9 34 92 40 00 8b 13 e8 7d ae ff ff 8b 45 e4 e8 6d f9 ff ff 83 c3 04 4e 75 dc 81 3d 9c 77 41 00 00 c0 00 00 7e 71 e8 52 fc ff ff eb 35 } //1
		$a_00_2 = {7c 1f bf 04 00 00 00 41 2d 00 00 64 a7 81 da b3 b6 e0 0d 73 f2 49 05 00 00 64 a7 81 d2 b3 b6 e0 0d 89 45 e0 89 55 e4 df 6d e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}