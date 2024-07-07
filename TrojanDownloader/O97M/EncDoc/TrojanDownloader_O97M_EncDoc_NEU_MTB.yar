
rule TrojanDownloader_O97M_EncDoc_NEU_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.NEU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 2e 27 44 6f 57 6e 6c 6f } //1 powershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnlo
		$a_01_1 = {68 74 74 70 3a 2f 2f 6f 66 66 69 63 65 2d 73 65 72 76 69 63 65 73 2d 73 65 63 2e 63 6f 6d 2f 63 72 69 6d 65 61 2e 70 73 31 } //1 http://office-services-sec.com/crimea.ps1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}