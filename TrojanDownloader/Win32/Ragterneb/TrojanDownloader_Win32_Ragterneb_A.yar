
rule TrojanDownloader_Win32_Ragterneb_A{
	meta:
		description = "TrojanDownloader:Win32/Ragterneb.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 00 65 00 76 00 5c 00 5f 00 65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 5f 00 68 00 6f 00 73 00 74 00 69 00 6e 00 67 00 } //1 dev\_exploit_hosting
		$a_01_1 = {5c 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 6c 00 69 00 73 00 74 00 } //1 \download.list
		$a_01_2 = {75 00 70 00 64 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 3f 00 6c 00 6f 00 63 00 61 00 6c 00 65 00 3d 00 } //1 update.php?locale=
		$a_01_3 = {5c 00 75 00 73 00 65 00 72 00 69 00 64 00 2e 00 64 00 61 00 74 00 } //1 \userid.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}