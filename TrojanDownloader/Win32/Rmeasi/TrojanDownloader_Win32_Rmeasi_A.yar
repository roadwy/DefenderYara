
rule TrojanDownloader_Win32_Rmeasi_A{
	meta:
		description = "TrojanDownloader:Win32/Rmeasi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2e 76 62 73 0a 65 63 68 6f 20 45 58 49 54 20 3e 3e 20 72 65 65 6d 2e 62 61 74 } //1
		$a_03_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? c7 45 ?? cf 07 00 00 eb 90 14 81 7d 90 1b 01 cf 07 00 00 0f 85 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}