
rule TrojanDownloader_O97M_Obfuse_TB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.TB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //01 00  Sub Auto_Open()
		$a_00_1 = {22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 } //01 00  "powershell.exe ""IEX ((new-object net.webclient)
		$a_00_2 = {2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f } //01 00  .downloadstring('http://
		$a_00_3 = {31 38 2e 31 34 31 2e 32 30 30 2e 39 35 2f 69 6d 67 2f 70 61 79 6c 6f 61 64 2e 74 78 74 } //01 00  18.141.200.95/img/payload.txt
		$a_00_4 = {53 68 65 6c 6c 20 28 65 78 65 63 29 } //00 00  Shell (exec)
	condition:
		any of ($a_*)
 
}