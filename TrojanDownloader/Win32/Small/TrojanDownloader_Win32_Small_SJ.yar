
rule TrojanDownloader_Win32_Small_SJ{
	meta:
		description = "TrojanDownloader:Win32/Small.SJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 65 74 75 70 5f 52 56 34 32 58 50 49 73 65 77 6f 2e 65 78 65 } //1 setup_RV42XPIsewo.exe
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 02 20 2f 4c 64 72 57 65 62 44 72 6f 70 41 70 70 7a 2f 90 02 40 2f 52 56 34 32 58 50 49 73 65 77 6f 2e 65 78 65 90 00 } //1
		$a_00_2 = {2f 53 50 2d 20 2f 73 75 70 70 72 65 73 73 6d 73 67 62 6f 78 65 73 20 2f 76 65 72 79 73 69 6c 65 6e 74 20 2f 6e 6f 69 63 6f 6e 73 20 2f 6e 6f 72 65 73 74 61 72 74 } //1 /SP- /suppressmsgboxes /verysilent /noicons /norestart
		$a_00_3 = {68 74 74 70 3a 2f 2f 31 37 34 2e 31 32 32 2e 32 34 30 2e 31 36 34 2f 4b 63 2f 32 33 33 31 } //1 http://174.122.240.164/Kc/2331
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}