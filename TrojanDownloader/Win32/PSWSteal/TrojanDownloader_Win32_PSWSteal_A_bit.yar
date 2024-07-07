
rule TrojanDownloader_Win32_PSWSteal_A_bit{
	meta:
		description = "TrojanDownloader:Win32/PSWSteal.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 URLDownloadToFile
		$a_03_1 = {68 74 74 70 73 3a 2f 2f 63 68 65 63 6b 61 6e 64 73 77 69 74 63 68 2e 63 6f 6d 2f 61 66 69 6c 65 2f 90 02 20 2e 65 78 65 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}