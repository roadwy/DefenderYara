
rule TrojanDownloader_Win16_Esverst_A{
	meta:
		description = "TrojanDownloader:Win16/Esverst.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 32 3d 76 73 77 77 6b 22 29 29 } //01 00  22=vswwk"))
		$a_01_1 = {28 22 68 7b 68 31 22 29 29 } //01 00  ("h{h1"))
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 } //00 00  CreateObject("WScript.Shell").Run Environ("temp") &
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}