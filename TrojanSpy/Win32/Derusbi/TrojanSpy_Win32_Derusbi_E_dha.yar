
rule TrojanSpy_Win32_Derusbi_E_dha{
	meta:
		description = "TrojanSpy:Win32/Derusbi.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 43 43 5f 43 4d 44 } //1 PCC_CMD
		$a_01_1 = {47 45 54 20 2f 50 68 6f 74 6f 73 2f 51 75 65 72 79 2e 63 67 69 3f 6c 6f 67 69 6e 69 64 3d } //1 GET /Photos/Query.cgi?loginid=
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //1 Software\Microsoft\Internet Account Manager\Accounts
		$a_00_3 = {5a 00 68 00 75 00 44 00 6f 00 6e 00 67 00 46 00 61 00 6e 00 67 00 59 00 75 00 2e 00 65 00 78 00 65 00 } //1 ZhuDongFangYu.exe
		$a_00_4 = {41 00 45 00 32 00 41 00 33 00 38 00 38 00 37 00 2d 00 41 00 33 00 30 00 41 00 2d 00 34 00 42 00 33 00 39 00 2d 00 41 00 35 00 45 00 36 00 2d 00 41 00 43 00 38 00 39 00 31 00 41 00 30 00 37 00 41 00 46 00 46 00 } //1 AE2A3887-A30A-4B39-A5E6-AC891A07AFF
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}