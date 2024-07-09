
rule TrojanDownloader_BAT_Muxif_A{
	meta:
		description = "TrojanDownloader:BAT/Muxif.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {28 16 00 00 0a 6f 17 00 00 0a ?? 28 15 00 00 0a 72 ?? 00 00 70 06 72 ?? 00 00 70 28 16 00 00 0a 28 18 00 00 0a } //1
		$a_00_1 = {71 77 65 31 32 33 2e 65 78 65 } //1 qwe123.exe
		$a_00_2 = {41 75 74 6f 52 75 6e } //1 AutoRun
		$a_00_3 = {66 00 69 00 6c 00 65 00 68 00 65 00 72 00 65 00 6c 00 6f 00 61 00 64 00 32 00 2e 00 72 00 75 00 2f 00 } //1 filehereload2.ru/
		$a_00_4 = {77 00 69 00 6e 00 33 00 32 00 5f 00 6c 00 6f 00 67 00 69 00 63 00 61 00 6c 00 64 00 69 00 73 00 6b 00 2e 00 64 00 65 00 76 00 69 00 63 00 65 00 69 00 64 00 3d 00 } //1 win32_logicaldisk.deviceid=
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}