
rule TrojanDownloader_O97M_Crosspim_A{
	meta:
		description = "TrojanDownloader:O97M/Crosspim.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 61 63 53 63 72 69 70 74 20 22 64 6f 20 73 68 65 6c 6c 20 73 63 72 69 70 74 20 22 22 28 63 75 72 6c 20 2d 73 } //01 00  MacScript "do shell script ""(curl -s
		$a_00_1 = {74 6f 6b 65 6e 3d 22 20 26 20 52 65 61 64 28 22 49 44 22 29 } //01 00  token=" & Read("ID")
		$a_00_2 = {52 65 61 64 28 22 4f 46 22 29 20 26 20 22 2e 70 6b 67 } //01 00  Read("OF") & ".pkg
		$a_00_3 = {43 6f 6d 70 75 74 65 72 4e 61 6d 65 22 29 20 26 20 76 62 4e 65 77 4c 69 6e 65 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 44 6f 6d 61 69 6e } //00 00  ComputerName") & vbNewLine & Environ("UserDomain
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}