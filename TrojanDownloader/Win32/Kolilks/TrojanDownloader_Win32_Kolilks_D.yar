
rule TrojanDownloader_Win32_Kolilks_D{
	meta:
		description = "TrojanDownloader:Win32/Kolilks.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 02 68 00 40 ff ff 53 ff 15 90 01 04 53 68 00 c0 00 00 bf 90 01 04 6a 01 57 ff 15 90 00 } //1
		$a_03_1 = {6a 05 ff 75 f8 ff 15 90 01 04 3d 5e 04 00 00 90 90 ff 15 90 01 04 6a 04 6a 00 ff 75 f8 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}