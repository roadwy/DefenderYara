
rule Trojan_Win32_Stelega_RF_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 89 f7 e8 90 01 04 01 f6 01 f6 09 f6 31 03 81 ee 80 d8 7d d6 01 ff 81 ee 90 00 } //1
		$a_00_1 = {81 c1 62 fe 43 51 81 e9 01 00 00 00 31 1f be 63 a3 dc 61 81 e9 30 31 01 56 f7 d1 47 89 c1 f7 d1 89 f1 81 c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Stelega_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Stelega.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 20 63 6f 72 72 75 70 74 65 64 } //1 File corrupted
		$a_81_1 = {69 74 27 73 20 69 6e 66 65 63 74 65 64 20 62 79 20 61 20 56 69 72 75 73 20 6f 72 20 63 72 61 63 6b 65 64 2e 20 54 68 69 73 20 66 69 6c 65 20 77 6f 6e 27 74 20 77 6f 72 6b 20 61 6e 79 6d 6f 72 65 } //10 it's infected by a Virus or cracked. This file won't work anymore
		$a_81_2 = {57 49 4e 48 54 54 50 2e 64 6c 6c } //1 WINHTTP.dll
		$a_81_3 = {50 61 74 68 46 69 6c 65 45 78 69 73 74 73 57 } //1 PathFileExistsW
		$a_81_4 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } //1 SHGetFolderPathA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}