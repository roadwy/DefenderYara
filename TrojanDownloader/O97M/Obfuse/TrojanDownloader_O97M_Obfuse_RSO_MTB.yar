
rule TrojanDownloader_O97M_Obfuse_RSO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 64 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 38 30 31 30 67 73 6b 73 31 2e 6a 70 67 22 2c 20 46 61 6c 73 65 } //01 00  xHttp.Open "GET", "https://d.top4top.io/p_18010gsks1.jpg", False
		$a_00_1 = {73 61 76 65 74 6f 66 69 6c 65 20 6a 20 26 20 22 2f 63 6c 69 65 6e 74 2e 76 62 73 22 2c 20 32 } //01 00  savetofile j & "/client.vbs", 2
		$a_00_2 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 22 20 26 20 6a 20 26 20 22 2f 63 6c 69 65 6e 74 2e 76 62 73 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //01 00  Shell "wscript " & j & "/client.vbs", vbNormalFocus
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 } //00 00  CreateObject("Adodb.Stream")
	condition:
		any of ($a_*)
 
}