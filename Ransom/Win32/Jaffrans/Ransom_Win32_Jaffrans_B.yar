
rule Ransom_Win32_Jaffrans_B{
	meta:
		description = "Ransom:Win32/Jaffrans.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_80_0 = {3c 74 69 74 6c 65 3e 6a 61 66 66 } //<title>jaff  1
		$a_80_1 = {59 6f 75 72 20 64 65 63 72 79 70 74 20 49 44 3a } //Your decrypt ID:  1
		$a_80_2 = {41 66 74 65 72 20 69 6e 73 74 61 6c 61 74 69 6f 6e 2c 20 72 75 6e 20 74 68 65 20 54 6f 72 20 42 72 6f 77 73 65 72 20 61 6e 64 20 65 6e 74 65 72 20 61 64 64 72 65 73 73 3a } //After instalation, run the Tor Browser and enter address:  1
		$a_80_3 = {54 6f 20 64 65 63 72 79 70 74 20 66 6c 69 65 73 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 6f 62 74 61 69 6e 20 74 68 65 20 70 72 69 76 61 74 65 } //To decrypt flies you need to obtain the private  1
		$a_01_4 = {89 45 f8 3d 00 00 08 00 76 0a b8 00 00 08 00 89 45 f8 eb 07 c7 45 fc 01 00 00 00 57 50 6a 08 } //2
		$a_03_5 = {8d 44 24 58 50 ff d6 85 c0 0f 84 ?? ?? 00 00 8d 4c 24 54 51 ff 15 ?? ?? ?? ?? f6 44 24 28 14 } //2
		$a_03_6 = {8b 45 f8 53 8d 55 e8 52 50 57 56 89 5d e8 ff 15 ?? ?? ?? ?? 8b 5d 0c 8d 4d f4 89 7d f4 51 8d 7d f8 e8 } //2
		$a_03_7 = {ff d7 6a 02 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 8b 55 ec 6a 00 8d 4d fc 51 52 53 56 ff d7 } //2
		$a_03_8 = {8d 43 41 51 66 89 55 f6 88 45 f0 ff 15 ?? ?? ?? ?? 83 f8 05 74 ?? 8d 55 f0 52 ff 15 ?? ?? ?? ?? 8d 44 00 02 } //2
		$a_03_9 = {ff d3 ff d3 3d 16 00 09 80 0f 85 ?? ?? ?? ?? 68 08 00 00 f0 6a 18 57 57 8d 4d fc 51 ff d6 } //2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*2+(#a_03_5  & 1)*2+(#a_03_6  & 1)*2+(#a_03_7  & 1)*2+(#a_03_8  & 1)*2+(#a_03_9  & 1)*2) >=8
 
}