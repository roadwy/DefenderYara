
rule Ransom_Win32_Zuresq_A{
	meta:
		description = "Ransom:Win32/Zuresq.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_03_0 = {28 60 00 00 06 13 90 01 01 45 08 00 00 00 00 00 00 00 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 02 80 11 90 01 01 13 90 01 01 11 90 01 01 20 90 01 02 00 00 28 60 00 00 06 30 90 01 01 18 45 01 00 00 00 f6 ff ff ff 90 02 10 20 90 01 02 00 00 28 60 00 00 06 2b 02 11 90 01 01 45 02 00 00 00 00 00 00 00 90 01 01 ff ff ff de 34 75 4b 00 00 01 14 fe 03 11 90 00 } //3
		$a_03_1 = {28 60 00 00 06 13 06 45 08 00 00 00 00 00 00 00 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 01 01 ff ff ff 90 02 06 11 07 13 06 11 05 20 90 00 } //3
		$a_00_2 = {47 65 74 42 69 74 63 6f 69 6e 41 64 64 72 65 73 73 } //1 GetBitcoinAddress
		$a_00_3 = {55 73 65 42 69 74 63 6f 69 6e 41 64 64 72 65 73 73 } //1 UseBitcoinAddress
		$a_00_4 = {45 6e 63 72 79 70 74 46 69 6c 65 73 } //1 EncryptFiles
		$a_00_5 = {44 65 63 72 79 70 74 46 69 6c 65 73 } //1 DecryptFiles
		$a_00_6 = {67 65 74 50 61 73 73 77 6f 72 64 } //1 getPassword
		$a_00_7 = {64 6c 44 65 73 6b 74 6f 70 46 69 6c 65 } //1 dlDesktopFile
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=9
 
}
rule Ransom_Win32_Zuresq_A_2{
	meta:
		description = "Ransom:Win32/Zuresq.A,SIGNATURE_TYPE_PEHSTR,03 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 61 6e 20 65 78 74 72 65 6d 65 6c 79 20 73 65 63 75 72 65 20 61 6e 64 20 75 6e 62 72 65 61 6b 61 62 6c 65 20 61 6c 67 6f 72 69 74 } //1 been encrypted using an extremely secure and unbreakable algorit
		$a_01_1 = {56 69 73 69 74 20 77 77 77 2e 6c 6f 63 61 6c 62 69 74 63 6f 69 6e 73 2e 63 6f 6d 20 74 6f 20 66 69 6e 64 20 61 20 73 65 6c 6c 65 72 20 69 6e 20 79 6f 75 72 20 61 72 65 61 2e } //1 Visit www.localbitcoins.com to find a seller in your area.
		$a_01_2 = {5c 00 52 00 75 00 6e 00 00 15 46 00 69 00 6c 00 65 00 52 00 65 00 73 00 63 00 75 00 65 00 00 } //1
		$a_01_3 = {5a 00 65 00 72 00 6f 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 00 0f 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 00 11 2e 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 00 29 68 00 74 00 74 00 70 00 } //1 ZeroLockerༀDesktopᄀ.encrypt⤀http
		$a_01_4 = {2f 00 70 00 61 00 74 00 72 00 69 00 6f 00 74 00 65 00 2f 00 73 00 61 00 6e 00 73 00 76 00 69 00 6f 00 6c 00 65 00 6e 00 63 00 65 00 00 1b 43 00 } //1 /patriote/sansviolenceᬀC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}