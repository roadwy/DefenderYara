
rule TrojanDownloader_O97M_Emotet_WASM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.WASM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 22 26 22 65 22 26 22 67 22 26 22 73 76 22 26 22 72 22 26 22 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 90 02 03 5c 57 22 26 22 69 6e 22 26 22 64 6f 22 26 22 77 22 26 22 73 5c 90 02 03 53 79 22 26 22 73 57 22 26 22 6f 77 22 26 22 36 22 26 22 34 5c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}