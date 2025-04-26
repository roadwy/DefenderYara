
rule Ransom_Win32_Cryptomix_A_{
	meta:
		description = "Ransom:Win32/Cryptomix.A!!Cryptomix.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //All your files have been encrypted!  1
		$a_80_1 = {2f 43 20 73 63 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 } ///C sc stop WinDefend  1
		$a_80_2 = {2f 43 20 73 63 20 73 74 6f 70 20 77 73 63 73 76 63 } ///C sc stop wscsvc  1
		$a_80_3 = {2f 43 20 73 63 20 73 74 6f 70 20 77 75 61 75 73 65 72 76 } ///C sc stop wuauserv  1
		$a_00_4 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 20 4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 51 55 41 41 34 47 4e 41 44 43 42 69 51 4b 42 67 } //1 -----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBg
		$a_03_5 = {53 6a 61 5b 6a 41 c7 45 ?? 1a 00 00 00 5a 0f b7 01 66 3b c3 72 ?? 83 f8 7a 77 ?? 83 e8 54 99 f7 7d ?? 03 d3 eb ?? 66 3b c2 72 ?? 83 f8 5a 77 ?? 83 e8 34 99 f7 7d ?? 83 c2 41 6a 41 } //3
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*3) >=5
 
}