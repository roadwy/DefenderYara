
rule TrojanDownloader_Win32_Carberp_Z{
	meta:
		description = "TrojanDownloader:Win32/Carberp.Z,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {62 6e 6b 2e 6c 69 73 74 00 } //1
		$a_01_1 = {b9 04 01 00 00 8d 68 0c c7 00 53 4d 53 54 89 48 04 89 48 08 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}