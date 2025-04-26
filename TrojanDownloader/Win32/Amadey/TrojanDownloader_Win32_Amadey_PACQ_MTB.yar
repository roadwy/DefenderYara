
rule TrojanDownloader_Win32_Amadey_PACQ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Amadey.PACQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 44 0c 10 04 73 88 84 0c a8 00 00 00 41 83 f9 09 7c ed } //1
		$a_01_1 = {8a 44 0c 2c 34 8a 88 84 0c f0 00 00 00 41 3b ca 7c ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}