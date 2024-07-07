
rule TrojanDownloader_Win32_Delf_HJ{
	meta:
		description = "TrojanDownloader:Win32/Delf.HJ,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 74 2e 65 78 65 00 00 00 55 8b ec 33 c0 55 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}