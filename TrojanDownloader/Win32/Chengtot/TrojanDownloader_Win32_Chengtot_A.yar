
rule TrojanDownloader_Win32_Chengtot_A{
	meta:
		description = "TrojanDownloader:Win32/Chengtot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 01 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 68 ?? ?? ?? 00 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? 00 8d 45 fc ba 12 00 00 00 e8 ?? ?? fe ff 8b 45 fc 50 ff 35 ?? ?? ?? ?? 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 ff 33 68 ?? ?? ?? 00 8d 45 f8 ba 06 00 00 00 } //1
		$a_02_1 = {68 74 74 70 [0-30] 3a 2f 2f [0-30] 64 72 [0-20] 76 [0-20] 33 32 [0-20] 2e [0-20] 64 61 74 61 [0-35] 2e 65 [0-20] 78 [0-20] 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}