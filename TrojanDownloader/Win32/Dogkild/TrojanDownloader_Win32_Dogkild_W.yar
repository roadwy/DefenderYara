
rule TrojanDownloader_Win32_Dogkild_W{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.W,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //1 SOFTWARE\Microsoft\windows\currentversion\run
		$a_00_1 = {52 75 6e 6d 65 41 74 53 74 61 72 74 75 70 } //1 RunmeAtStartup
		$a_00_2 = {3f 75 69 64 3d 25 73 26 61 64 64 72 65 73 73 3d 25 73 26 70 3d 25 64 26 61 3d 25 64 } //1 ?uid=%s&address=%s&p=%d&a=%d
		$a_00_3 = {68 74 74 70 3a 2f 2f 66 75 2e 6f 33 73 62 2e 63 6f 6d 3a 39 39 39 39 2f 69 6d 67 2e 6a 70 67 } //1 http://fu.o3sb.com:9999/img.jpg
		$a_02_4 = {68 74 74 70 3a 2f 2f 90 02 20 3a 90 01 04 2f 90 02 08 2f 72 6b 32 33 2e 65 78 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}