
rule TrojanDownloader_Win32_BlackMoon_YA_MTB{
	meta:
		description = "TrojanDownloader:Win32/BlackMoon.YA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70 } //1 certutil.exe -urlcache -split -f http
		$a_01_1 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}