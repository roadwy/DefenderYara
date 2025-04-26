
rule Worm_Win32_Koobface_U{
	meta:
		description = "Worm:Win32/Koobface.U,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 63 72 63 3d 25 64 } //1 &crc=%d
		$a_01_1 = {26 63 5f 62 65 3d 25 64 26 63 5f 74 67 3d 25 64 26 63 5f 6e 6c 3d 25 64 26 69 65 64 65 66 3d 25 64 } //1 &c_be=%d&c_tg=%d&c_nl=%d&iedef=%d
		$a_01_2 = {26 63 5f 66 62 3d 25 64 26 63 5f 6d 73 3d 25 64 26 63 5f 68 69 3d 25 64 26 63 5f 74 77 3d 25 64 } //1 &c_fb=%d&c_ms=%d&c_hi=%d&c_tw=%d
		$a_01_3 = {43 4c 53 49 44 5c 7b 46 44 36 39 30 35 43 45 2d 39 35 32 46 2d 34 31 46 31 2d 39 41 36 46 2d 31 33 35 44 39 43 36 36 32 32 43 43 7d } //1 CLSID\{FD6905CE-952F-41F1-9A6F-135D9C6622CC}
		$a_01_4 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 http\shell\open\command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}