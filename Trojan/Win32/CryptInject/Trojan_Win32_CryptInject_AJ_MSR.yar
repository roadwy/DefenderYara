
rule Trojan_Win32_CryptInject_AJ_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.AJ!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 72 70 75 64 6d 76 6e 64 6c 69 76 65 62 74 68 } //1 nrpudmvndlivebth
		$a_01_1 = {54 72 61 63 6b 50 6f 70 75 70 4d 65 6e 75 } //1 TrackPopupMenu
		$a_01_2 = {63 3a 5c 74 65 6d 70 5c 41 75 74 6f 57 61 6c 6c 70 61 70 65 72 2e 62 6d 70 } //1 c:\temp\AutoWallpaper.bmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}