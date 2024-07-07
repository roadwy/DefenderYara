
rule TrojanDownloader_Win32_Loctor_A{
	meta:
		description = "TrojanDownloader:Win32/Loctor.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {54 68 65 20 4c 75 61 4f 72 62 20 52 65 61 63 74 6f 72 00 00 73 65 74 75 70 2e 65 78 65 } //1
		$a_03_1 = {6a 00 ff 15 90 01 04 89 85 90 01 02 ff ff c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 00 8b 8d 90 01 02 ff ff 90 02 02 ff 00 00 00 8b 90 01 03 ff ff 90 02 02 ff 00 00 00 3b 90 01 01 0f 85 be 00 00 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}