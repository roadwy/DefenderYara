
rule TrojanSpy_Win32_Banker_AHP{
	meta:
		description = "TrojanSpy:Win32/Banker.AHP,SIGNATURE_TYPE_PEHSTR_EXT,50 00 46 00 0a 00 00 14 00 "
		
	strings :
		$a_01_0 = {6c 69 71 75 69 67 61 73 2e 69 74 2f 69 6d 6d 61 67 69 6e 69 2f 69 6e 66 6f 72 6d 61 2e 70 68 70 } //14 00  liquigas.it/immagini/informa.php
		$a_01_1 = {4f 64 39 58 50 36 4c 70 4f 73 7a 6b 50 4e 48 62 52 4e 31 6f 50 4e 44 58 42 63 44 6c 52 49 76 59 } //14 00  Od9XP6LpOszkPNHbRN1oPNDXBcDlRIvY
		$a_01_2 = {51 37 48 71 53 37 43 77 42 6f 7a 59 53 63 35 61 50 4e 44 5a 52 73 76 62 54 36 4c 6a 53 37 39 62 53 73 34 6b 4f 73 7a 6a 42 63 } //14 00  Q7HqS7CwBozYSc5aPNDZRsvbT6LjS79bSs4kOszjBc
		$a_01_3 = {47 64 39 58 50 36 4c 70 4f 73 79 } //0a 00  Gd9XP6LpOsy
		$a_01_4 = {4b 71 7a 36 4c 35 54 31 4b 61 4c 53 4a 4b 62 33 4b 61 7a 4a 4a 71 50 4b 4e 35 54 39 4a 61 48 46 } //0a 00  Kqz6L5T1KaLSJKb3KazJJqPKN5T9JaHF
		$a_01_5 = {4e 35 44 6c 50 64 48 74 4f 4e 39 62 4e 34 72 66 4f 74 39 6c 53 73 7a 63 54 35 6e 39 52 64 48 62 } //0a 00  N5DlPdHtON9bN4rfOt9lSszcT5n9RdHb
		$a_01_6 = {51 4d 76 63 52 74 39 6a 4f 49 76 71 55 37 47 } //0a 00  QMvcRt9jOIvqU7G
		$a_01_7 = {54 37 48 66 52 4d 4c 58 4f 73 4c 70 53 73 79 6b 54 37 58 71 } //05 00  T7HfRMLXOsLpSsykT7Xq
		$a_01_8 = {51 4d 4c 75 53 36 6e 6c 53 63 4c 6f } //05 00  QMLuS6nlScLo
		$a_01_9 = {4c 63 4c 6f 53 73 62 6c 52 57 } //00 00  LcLoSsblRW
	condition:
		any of ($a_*)
 
}