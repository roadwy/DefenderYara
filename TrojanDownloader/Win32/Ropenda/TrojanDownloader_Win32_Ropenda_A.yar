
rule TrojanDownloader_Win32_Ropenda_A{
	meta:
		description = "TrojanDownloader:Win32/Ropenda.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 35 cc 00 00 00 8b 8d 90 01 02 ff ff 03 8d 90 01 02 ff ff 88 01 eb c2 90 00 } //1
		$a_01_1 = {25 73 3f 76 3d 25 64 00 } //1 猥瘿┽d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}