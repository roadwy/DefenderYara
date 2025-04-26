
rule TrojanDownloader_Win32_Zlob_ZWP{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ZWP,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 61 72 61 6d 3d 25 73 00 00 00 00 25 73 2f 61 63 63 65 73 73 2f 67 6f 2e 70 68 70 00 00 00 00 32 31 36 2e 32 35 35 2e 31 38 37 2e 39 31 00 00 2f 6b 65 79 2f 73 65 63 72 65 74 6b 65 79 2e 69 6e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}