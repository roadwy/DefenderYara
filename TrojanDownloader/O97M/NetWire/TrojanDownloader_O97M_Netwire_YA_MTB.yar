
rule TrojanDownloader_O97M_Netwire_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Netwire.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 66 66 69 63 65 73 65 72 76 69 63 65 63 6f 72 70 2e 62 69 7a 2f } //01 00  officeservicecorp.biz/
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 } //00 00  powershell.exe -Command IEX (New-Object('Net.WebClient'))
	condition:
		any of ($a_*)
 
}