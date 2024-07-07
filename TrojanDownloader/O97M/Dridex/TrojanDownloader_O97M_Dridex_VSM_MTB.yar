
rule TrojanDownloader_O97M_Dridex_VSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.VSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 20 22 6d 73 68 74 61 2e 65 78 65 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6c 7a 51 42 67 59 4b 6c 76 4f 50 6e 6f 44 72 76 4a 41 47 67 77 50 4f 2e 72 74 66 } //1 create "mshta.exe C:\ProgramData\lzQBgYKlvOPnoDrvJAGgwPO.rtf
	condition:
		((#a_01_0  & 1)*1) >=1
 
}