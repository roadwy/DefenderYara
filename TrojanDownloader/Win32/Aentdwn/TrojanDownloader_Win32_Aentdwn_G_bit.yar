
rule TrojanDownloader_Win32_Aentdwn_G_bit{
	meta:
		description = "TrojanDownloader:Win32/Aentdwn.G!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {35 00 2e 00 32 00 30 00 30 00 2e 00 35 00 32 00 2e 00 35 00 31 00 90 02 2f 64 00 61 00 74 00 61 00 90 00 } //1
		$a_03_1 = {73 00 74 00 61 00 72 00 74 00 90 02 2f 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}