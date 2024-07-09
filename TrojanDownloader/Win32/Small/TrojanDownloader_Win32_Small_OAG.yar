
rule TrojanDownloader_Win32_Small_OAG{
	meta:
		description = "TrojanDownloader:Win32/Small.OAG,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 2f 00 10 15 6a 02 e8 ?? ?? ff ff 83 c4 08 6a 00 6a 00 6a 00 6a 00 6a 00 68 ?? 20 40 00 68 ?? 20 40 00 55 ff d0 } //10
		$a_00_1 = {6c 6f 61 64 73 2e 70 68 70 } //10 loads.php
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}