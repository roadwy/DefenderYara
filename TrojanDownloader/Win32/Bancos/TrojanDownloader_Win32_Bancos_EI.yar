
rule TrojanDownloader_Win32_Bancos_EI{
	meta:
		description = "TrojanDownloader:Win32/Bancos.EI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 5c 61 6c 67 2e 65 78 65 } //03 00 
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 25 73 20 2f 74 72 20 25 73 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 75 20 22 4e 54 20 41 55 54 48 4f 52 49 54 59 5c 53 59 53 54 45 4d 22 } //02 00 
		$a_01_2 = {5c 42 4b 36 36 2e 6c 6f 67 } //01 00 
		$a_01_3 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}