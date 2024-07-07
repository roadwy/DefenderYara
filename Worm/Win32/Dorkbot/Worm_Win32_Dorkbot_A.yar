
rule Worm_Win32_Dorkbot_A{
	meta:
		description = "Worm:Win32/Dorkbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 50 68 d0 37 10 f2 68 50 40 40 00 56 ff 51 20 85 c0 } //1
		$a_01_1 = {6e 00 41 00 6e 00 64 00 72 00 20 00 68 00 75 00 74 00 74 00 61 00 50 00 2e 00 76 00 62 00 70 00 } //1 nAndr huttaP.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Worm_Win32_Dorkbot_A_2{
	meta:
		description = "Worm:Win32/Dorkbot.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 00 00 00 00 38 00 16 00 01 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 44 00 6e 00 4b 00 41 00 73 00 65 00 65 00 59 00 4f 00 55 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Worm_Win32_Dorkbot_A_3{
	meta:
		description = "Worm:Win32/Dorkbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 20 25 25 63 64 25 25 52 45 43 59 43 4c 45 52 5c 25 73 } //1 start %%cd%%RECYCLER\%s
		$a_00_1 = {6e 67 72 42 6f 74 } //1 ngrBot
		$a_03_2 = {83 c4 0c 53 8d 45 f8 50 68 00 04 00 00 8d 8d 90 01 02 ff ff 51 6a 0c 8d 55 90 01 01 52 68 00 14 2d 00 56 c7 85 90 01 02 ff ff 00 04 00 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Worm_Win32_Dorkbot_A_4{
	meta:
		description = "Worm:Win32/Dorkbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 20 46 40 00 e8 da 45 ff ff 85 c0 75 19 ff 35 50 00 41 00 68 b4 40 40 00 e8 ba 45 ff ff } //1
		$a_01_1 = {41 00 44 00 3a 00 5c 00 43 00 61 00 6d 00 62 00 69 00 61 00 64 00 6f 00 72 00 2e 00 76 00 62 00 70 00 } //1 AD:\Cambiador.vbp
		$a_01_2 = {64 00 44 00 31 00 42 00 32 00 30 00 41 00 34 00 30 00 2d 00 35 00 39 00 44 00 35 00 2d 00 31 00 30 00 31 00 42 00 2d 00 41 00 33 00 43 00 39 00 2d 00 30 00 38 00 30 00 30 00 32 00 42 00 32 00 46 00 34 00 39 00 46 00 42 00 } //1 dD1B20A40-59D5-101B-A3C9-08002B2F49FB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Worm_Win32_Dorkbot_A_5{
	meta:
		description = "Worm:Win32/Dorkbot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 00 6f 00 75 00 27 00 76 00 65 00 20 00 6a 00 75 00 73 00 74 00 20 00 62 00 65 00 65 00 6e 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 50 00 65 00 6e 00 6a 00 61 00 67 00 61 00 20 00 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 } //1 You've just been protected by Penjaga Firewall
		$a_01_1 = {8b 85 dc fe ff ff 89 85 64 fb ff ff 83 a5 dc fe ff ff 00 68 58 7b 40 00 e8 d4 57 fd ff } //1
		$a_01_2 = {74 00 39 00 33 00 36 00 38 00 32 00 36 00 35 00 45 00 2d 00 38 00 35 00 46 00 45 00 2d 00 31 00 31 00 64 00 31 00 2d 00 38 00 42 00 45 00 33 00 2d 00 30 00 30 00 30 00 30 00 46 00 38 00 37 00 35 00 34 00 44 00 41 00 31 00 } //1 t9368265E-85FE-11d1-8BE3-0000F8754DA1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}