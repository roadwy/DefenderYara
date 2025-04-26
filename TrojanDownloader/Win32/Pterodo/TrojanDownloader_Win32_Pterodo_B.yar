
rule TrojanDownloader_Win32_Pterodo_B{
	meta:
		description = "TrojanDownloader:Win32/Pterodo.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 74 6f 6c 6f 61 64 3d 7b } //1 urltoload={
		$a_01_1 = {20 2f 63 73 73 2e 70 68 70 3f 69 64 3d } //1  /css.php?id=
		$a_01_2 = {2e 64 6c 6c 00 62 69 74 44 65 66 65 6e 64 65 72 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}