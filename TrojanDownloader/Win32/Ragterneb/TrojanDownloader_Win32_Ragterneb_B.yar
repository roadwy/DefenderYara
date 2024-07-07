
rule TrojanDownloader_Win32_Ragterneb_B{
	meta:
		description = "TrojanDownloader:Win32/Ragterneb.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 00 65 00 76 00 5c 00 5f 00 77 00 69 00 6e 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 } //1 dev\_win_updater
		$a_00_1 = {2e 00 65 00 78 00 65 00 20 00 2f 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 } //1 .exe /autorun
		$a_02_2 = {75 00 70 00 64 00 61 00 74 00 65 00 5f 00 6c 00 6f 00 67 00 67 00 65 00 72 00 90 02 04 2e 00 70 00 68 00 70 00 3f 00 6c 00 6f 00 63 00 61 00 6c 00 65 00 3d 00 90 00 } //1
		$a_00_3 = {5c 00 75 00 73 00 65 00 72 00 69 00 64 00 2e 00 64 00 61 00 74 00 } //1 \userid.dat
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}