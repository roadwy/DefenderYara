
rule TrojanDownloader_Win32_Gdrexc_YA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Gdrexc.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 63 3f 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 26 69 64 3d } //1 uc?export=download&id=
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 25 61 70 70 64 61 74 61 25 } //1 cmd.exe /c "%appdata%
		$a_01_2 = {64 72 69 76 65 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //1 drive.google.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}