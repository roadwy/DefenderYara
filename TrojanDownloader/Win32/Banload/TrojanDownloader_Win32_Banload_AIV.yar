
rule TrojanDownloader_Win32_Banload_AIV{
	meta:
		description = "TrojanDownloader:Win32/Banload.AIV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2f 74 65 6d 70 73 62 72 61 73 69 6c 2e 6e 65 74 2f 90 02 18 2e 65 78 65 90 02 08 63 6d 64 20 2f 6b 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 90 02 18 2e 65 78 65 90 02 05 55 8b ec 6a 00 33 c0 55 68 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}