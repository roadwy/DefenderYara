
rule Trojan_Win32_Derusbi_C_dha{
	meta:
		description = "Trojan:Win32/Derusbi.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 63 65 31 32 33 64 78 } //1 Ace123dx
		$a_00_1 = {4c 6f 61 64 43 6f 6e 66 69 67 46 72 6f 6d 52 65 67 20 66 61 69 6c 64 65 64 } //1 LoadConfigFromReg failded
		$a_00_2 = {4c 6f 61 64 43 6f 6e 66 69 67 46 72 6f 6d 42 75 69 6c 64 69 6e 20 73 75 63 63 65 73 73 } //1 LoadConfigFromBuildin success
		$a_00_3 = {2f 70 68 6f 74 6f 65 2f 70 68 6f 74 6f 2e 61 73 70 20 48 54 54 50 } //1 /photoe/photo.asp HTTP
		$a_01_4 = {7e 44 46 54 4d 50 24 24 24 24 24 2e 31 } //1 ~DFTMP$$$$$.1
		$a_01_5 = {44 6f 6d 34 21 6e 55 73 65 72 50 34 73 73 } //1 Dom4!nUserP4ss
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}