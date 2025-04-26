
rule Virus_Win32_Minipg_B_bit{
	meta:
		description = "Virus:Win32/Minipg.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 69 50 69 67 20 62 79 20 5b 57 61 72 47 61 6d 65 2c 23 65 6f 66 5d } //1 MiniPig by [WarGame,#eof]
		$a_01_1 = {25 63 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //1 %c%c%c%c%c%c.exe
		$a_01_2 = {8b 55 e8 8b 45 f4 01 d0 8b 4d e8 8b 55 f4 01 ca 0f b6 12 83 f2 4a 88 10 83 45 f4 01 } //1
		$a_01_3 = {8b 45 f0 8b 55 dc 01 c2 8b 45 f0 03 45 dc 0f b6 00 34 4a 88 02 8d 45 dc ff 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}