
rule TrojanDownloader_Win32_Wrokni_A_{
	meta:
		description = "TrojanDownloader:Win32/Wrokni.A!!Wrokni.A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 61 6e 27 74 20 6c 6f 61 64 20 74 68 65 20 62 75 66 31 } //2 can't load the buf1
		$a_00_1 = {5b 64 6c 5d 20 64 6f 77 6e 20 61 6c 6c 70 61 74 68 20 3d } //1 [dl] down allpath =
		$a_00_2 = {5b 64 6c 5d 20 73 68 65 6c 6c 20 72 65 74 20 3d } //1 [dl] shell ret =
		$a_00_3 = {5b 64 6c 5d 20 75 72 6c 20 3d } //1 [dl] url =
		$a_00_4 = {68 74 74 70 3a 2f 2f 00 2e 6f 6e 6c 69 6e 65 2f } //1 瑨灴⼺/漮汮湩⽥
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}