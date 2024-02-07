
rule TrojanDownloader_BAT_Bsymem_ABS_MTB{
	meta:
		description = "TrojanDownloader:BAT/Bsymem.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 00 69 00 61 00 64 00 65 00 63 00 6f 00 6d 00 70 00 72 00 61 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 74 00 75 00 62 00 73 00 2f 00 45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 2e 00 74 00 78 00 74 00 } //02 00  ciadecompras.com/stubs/Encoding.txt
		$a_01_1 = {56 31 4b 31 4e 47 5c 4f 6e 65 44 72 69 76 65 5c 44 65 73 6b 74 6f 70 5c 42 4f 54 4e 45 54 20 54 4f 4f 4c 53 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 5c 6f 62 6a 5c 44 65 62 75 67 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 70 64 62 } //01 00  V1K1NG\OneDrive\Desktop\BOTNET TOOLS\WindowsFormsApp1\WindowsFormsApp1\obj\Debug\WindowsFormsApp1.pdb
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 31 00 2e 00 65 00 78 00 65 00 } //00 00  WindowsFormsApp1.exe
	condition:
		any of ($a_*)
 
}