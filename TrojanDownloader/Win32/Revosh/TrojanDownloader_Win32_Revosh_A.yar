
rule TrojanDownloader_Win32_Revosh_A{
	meta:
		description = "TrojanDownloader:Win32/Revosh.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {37 00 36 00 2e 00 31 00 39 00 31 00 2e 00 31 00 31 00 32 00 2e 00 32 00 2f 00 72 00 65 00 63 00 76 00 2e 00 70 00 68 00 70 00 } //02 00  76.191.112.2/recv.php
		$a_01_1 = {6e 00 61 00 6d 00 65 00 3d 00 22 00 75 00 70 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 22 00 3b 00 20 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 3d 00 22 00 } //01 00  name="uploadfile"; filename="
		$a_01_2 = {52 65 6d 6f 74 65 53 68 6f 74 } //01 00  RemoteShot
		$a_01_3 = {73 00 68 00 6f 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  shot.exe
		$a_00_4 = {5d 04 00 } //00 c8 
	condition:
		any of ($a_*)
 
}