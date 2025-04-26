
rule Backdoor_Win32_Wavipeg_B{
	meta:
		description = "Backdoor:Win32/Wavipeg.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {61 76 70 00 65 73 65 74 00 65 67 75 69 } //1
		$a_01_1 = {64 64 6f 73 26 63 6f 6d 70 3d 25 73 } //1 ddos&comp=%s
		$a_01_2 = {26 63 6f 6d 70 3d 25 73 26 65 78 74 3d } //1 &comp=%s&ext=
		$a_01_3 = {25 73 3f 67 65 74 26 65 78 65 26 63 6f 6d 70 3d 25 73 } //1 %s?get&exe&comp=%s
		$a_01_4 = {25 73 3f 63 73 74 6f 72 61 67 65 3d 64 64 6f 73 } //1 %s?cstorage=ddos
		$a_01_5 = {25 73 3f 67 65 74 26 64 6f 77 6e 6c 6f 61 64 26 63 6f 6d 70 3d 25 73 } //1 %s?get&download&comp=%s
		$a_01_6 = {25 73 3f 67 65 74 26 6d 6f 64 75 6c 65 3d 25 73 26 63 6f 6d 70 3d 25 73 } //1 %s?get&module=%s&comp=%s
		$a_01_7 = {25 73 3f 65 6e 63 26 63 6f 6d 70 3d 25 73 26 65 78 74 3d 63 6c 69 70 62 6f 61 72 64 2e 74 78 74 26 75 70 6c 6f 61 64 5f 74 65 78 74 3d 25 73 } //1 %s?enc&comp=%s&ext=clipboard.txt&upload_text=%s
		$a_01_8 = {25 73 3f 65 6e 63 26 63 6f 6d 70 3d 25 73 26 65 78 74 3d 73 79 73 69 6e 66 6f 2e 74 78 74 26 75 70 6c 6f 61 64 5f 74 65 78 74 3d 25 73 } //1 %s?enc&comp=%s&ext=sysinfo.txt&upload_text=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}