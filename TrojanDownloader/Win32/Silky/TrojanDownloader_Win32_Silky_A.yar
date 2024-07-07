
rule TrojanDownloader_Win32_Silky_A{
	meta:
		description = "TrojanDownloader:Win32/Silky.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {63 3a 5c 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 90 01 0c 68 74 74 70 3a 2f 2f 90 02 65 63 6d 64 20 2f 6b 20 63 3a 5c 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 00 55 8b ec 6a 00 33 c0 55 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}