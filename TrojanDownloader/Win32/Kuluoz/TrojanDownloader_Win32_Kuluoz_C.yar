
rule TrojanDownloader_Win32_Kuluoz_C{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 72 3d 25 31 30 32 34 5b 5e 26 5d 26 61 3d 25 78 26 6b 3d 25 78 26 6e 3d 25 31 30 32 34 73 } //1 &r=%1024[^&]&a=%x&k=%x&n=%1024s
		$a_01_1 = {63 3d 75 70 64 26 72 3d 25 31 30 32 34 73 } //1 c=upd&r=%1024s
		$a_01_2 = {25 31 30 32 34 5b 5e 3d 5d 3d 25 31 30 32 34 5b 5e 3b 5d } //1 %1024[^=]=%1024[^;]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Kuluoz_C_2{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3d 72 64 6c 26 75 3d 25 31 30 32 34 5b 5e 26 5d 26 61 3d 25 78 26 6b 3d 25 78 26 6e 3d 25 31 30 32 34 73 } //1 c=rdl&u=%1024[^&]&a=%x&k=%x&n=%1024s
		$a_01_1 = {63 3d 72 75 6e 26 75 3d 25 31 30 32 34 73 } //1 c=run&u=%1024s
		$a_01_2 = {25 31 30 32 34 5b 5e 3d 5d 3d 25 31 30 32 34 5b 5e 3b 5d } //1 %1024[^=]=%1024[^;]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}