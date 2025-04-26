
rule TrojanDownloader_Win32_Seraph_PABQ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Seraph.PABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 31 35 35 2e 39 34 2e 31 32 39 2e 34 2f 7a 69 6a 69 6c 75 6f 6c 69 2e 62 69 6e } //1 //155.94.129.4/zijiluoli.bin
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 32 63 32 61 6f 2e 70 6e 67 } //1 C:\ProgramData\2c2ao.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}