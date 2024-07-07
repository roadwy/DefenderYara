
rule TrojanDownloader_Win32_Sdc_A{
	meta:
		description = "TrojanDownloader:Win32/Sdc.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 51 50 65 74 4c 6f 76 65 2e 64 6c 6c 00 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 6e 61 6a 74 2e 63 6f 6d 2e 63 6e 2f 73 64 2e 65 78 65 00 01 00 00 00 00 00 00 00 63 3a 5c 63 2e 65 78 65 00 38 00 00 00 6d 2f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}