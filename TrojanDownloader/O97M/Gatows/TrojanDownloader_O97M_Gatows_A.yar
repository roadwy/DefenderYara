
rule TrojanDownloader_O97M_Gatows_A{
	meta:
		description = "TrojanDownloader:O97M/Gatows.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 57 49 4e 44 4f 57 53 2e 4c 61 62 65 6c [0-02] 2e 54 61 67 } //1
		$a_00_1 = {2e 52 75 6e 20 57 49 4e 44 4f 57 53 2e 4c 61 62 65 6c 31 2e 54 61 67 20 2b 20 22 20 22 20 26 20 57 49 4e 44 4f 57 53 2e 54 61 67 20 2b } //1 .Run WINDOWS.Label1.Tag + " " & WINDOWS.Tag +
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}