
rule TrojanDownloader_Win32_Alureon_G{
	meta:
		description = "TrojanDownloader:Win32/Alureon.G,SIGNATURE_TYPE_PEHSTR_EXT,23 00 22 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {5c 69 6e 65 74 63 2e 64 6c 6c } //0a 00  \inetc.dll
		$a_00_1 = {5c 45 78 65 63 50 72 69 2e 64 6c 6c } //0a 00  \ExecPri.dll
		$a_00_2 = {45 78 65 63 57 61 69 74 } //04 00  ExecWait
		$a_02_3 = {68 74 74 70 3a 2f 2f 69 6e 6c 69 6e 65 34 37 37 2e 69 6e 66 6f 2f 66 73 72 76 90 02 20 2e 65 78 65 90 00 } //01 00 
		$a_00_4 = {5c 77 6f 77 72 65 67 33 32 61 2e 65 78 65 } //01 00  \wowreg32a.exe
		$a_00_5 = {5c 66 69 6e 67 65 72 62 2e 65 78 65 } //01 00  \fingerb.exe
		$a_00_6 = {5c 66 69 78 6d 61 70 69 62 2e 65 78 65 } //01 00  \fixmapib.exe
		$a_00_7 = {5c 61 74 69 65 73 72 78 78 62 2e 65 78 65 } //01 00  \atiesrxxb.exe
		$a_00_8 = {5c 50 41 54 48 50 49 4e 47 62 2e 65 78 65 } //00 00  \PATHPINGb.exe
	condition:
		any of ($a_*)
 
}