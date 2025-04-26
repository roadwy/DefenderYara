
rule TrojanDownloader_Win32_Zlob_gen_AAB{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AAB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {38 31 2e 30 2e 32 35 30 2e 34 37 } //1 81.0.250.47
		$a_01_1 = {25 73 3f 76 65 72 73 69 6f 6e 3d 25 73 26 63 6e 3d 25 73 26 63 6f 6e 74 79 70 65 3d 25 64 26 70 69 64 3d 25 64 } //1 %s?version=%s&cn=%s&contype=%d&pid=%d
		$a_01_2 = {43 6c 69 63 6b 4e 75 6d } //1 ClickNum
		$a_01_3 = {25 73 3f 69 64 5f 6e 75 6d 3d 25 64 26 74 65 78 74 3d 25 73 } //1 %s?id_num=%d&text=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}