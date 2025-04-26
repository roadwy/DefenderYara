
rule TrojanDownloader_Win32_Sudesroc_A{
	meta:
		description = "TrojanDownloader:Win32/Sudesroc.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 00 77 00 2e 00 75 00 73 00 73 00 6f 00 63 00 63 00 65 00 72 00 6b 00 69 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 6d 00 69 00 6e 00 } //2 ww.ussoccerkit.com/min
		$a_01_1 = {2f 00 6c 00 69 00 62 00 2f 00 53 00 75 00 72 00 66 00 2e 00 7a 00 69 00 70 00 } //2 /lib/Surf.zip
		$a_01_2 = {64 00 65 00 75 00 73 00 40 00 35 00 35 00 } //2 deus@55
		$a_01_3 = {5c 00 65 00 72 00 65 00 61 00 64 00 65 00 72 00 73 00 61 00 77 00 2e 00 65 00 78 00 65 00 } //1 \ereadersaw.exe
		$a_01_4 = {5c 00 6c 00 69 00 73 00 63 00 75 00 2e 00 65 00 78 00 65 00 } //1 \liscu.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}