
rule TrojanDownloader_O97M_Ursnif_SJT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.SJT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 3d 20 22 68 74 74 70 3a 2f 2f 69 6e 74 65 72 22 20 26 20 90 02 0f 20 26 20 4f 72 69 6f 73 20 26 20 22 2e 63 6f 6d 22 90 00 } //01 00 
		$a_01_1 = {20 3d 20 2e 52 75 6e 28 50 6c 20 26 20 22 20 20 49 6e 65 74 43 70 6c 2e 63 70 6c 2c 43 6c 65 61 72 4d 79 54 72 61 63 6b 73 42 79 50 72 6f 63 65 73 73 20 32 35 35 22 2c 20 30 2c 20 54 72 75 65 29 3a 20 45 6e 64 20 57 69 74 68 } //01 00   = .Run(Pl & "  InetCpl.cpl,ClearMyTracksByProcess 255", 0, True): End With
		$a_03_2 = {28 49 6e 74 28 90 02 0f 20 2a 20 52 6e 64 29 20 2b 20 90 02 0f 29 20 26 20 22 2e 63 76 73 22 90 00 } //01 00 
		$a_01_3 = {3d 20 22 2c 23 22 20 26 20 4c 65 6e 28 6f 58 48 54 54 50 2e 67 65 74 52 65 73 70 6f 6e 73 65 48 65 61 64 65 72 28 22 41 6b 61 6d 61 69 2d 47 52 4e 22 29 29 } //00 00  = ",#" & Len(oXHTTP.getResponseHeader("Akamai-GRN"))
	condition:
		any of ($a_*)
 
}