
rule TrojanDownloader_WinNT_Banload_W{
	meta:
		description = "TrojanDownloader:WinNT/Banload.W,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 41 64 6d 69 6e 69 73 74 72 61 64 6f 72 5c 74 65 73 74 65 2e 7a 69 70 } //01 00  \Administrador\teste.zip
		$a_01_1 = {2e 7a 69 70 3f 61 74 74 72 65 64 69 72 65 63 74 73 3d 30 26 64 3d 31 } //01 00  .zip?attredirects=0&d=1
		$a_01_2 = {5c 63 72 79 70 74 73 2e 64 6c 6c 2c 43 65 72 74 65 7a 61 } //00 00  \crypts.dll,Certeza
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}