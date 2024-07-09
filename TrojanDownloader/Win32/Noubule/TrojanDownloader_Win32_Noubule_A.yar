
rule TrojanDownloader_Win32_Noubule_A{
	meta:
		description = "TrojanDownloader:Win32/Noubule.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 68 0c fe ff ff 56 ff 15 ?? ?? 40 00 68 f4 01 00 00 e8 ?? ?? 00 00 83 c4 04 8d 55 fc 8b f8 6a 00 52 68 f4 01 00 00 } //2
		$a_01_1 = {25 73 3f 6d 61 63 3d 25 73 } //1 %s?mac=%s
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=2
 
}