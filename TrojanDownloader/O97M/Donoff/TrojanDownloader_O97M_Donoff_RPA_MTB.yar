
rule TrojanDownloader_O97M_Donoff_RPA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RPA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 22 2c 22 75 70 64 61 74 69 6e 67 22 2c 22 63 6f 6e 68 6f 73 74 6d 73 68 74 61 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f } //1 software\microsoft\windows\currentversion\run","updating","conhostmshtahttp://www.j.mp/
	condition:
		((#a_01_0  & 1)*1) >=1
 
}