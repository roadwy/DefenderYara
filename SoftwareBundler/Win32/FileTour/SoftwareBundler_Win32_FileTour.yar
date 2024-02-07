
rule SoftwareBundler_Win32_FileTour{
	meta:
		description = "SoftwareBundler:Win32/FileTour,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 76 67 65 6e 20 4b 75 67 69 74 6b 6f } //01 00  Evgen Kugitko
		$a_01_1 = {32 65 37 34 36 66 37 32 37 32 36 35 36 65 37 34 } //01 00  2e746f7272656e74
		$a_01_2 = {68 6f 72 73 65 73 2e 66 69 6c 65 2d 74 6f 75 72 2e 72 75 } //01 00  horses.file-tour.ru
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 73 2f 76 5f 69 6e 73 74 61 6c 6c 3f 73 69 64 3d 31 36 30 34 35 26 73 74 61 72 74 3d 31 26 67 75 69 64 3d 24 5f 5f 47 55 49 44 26 73 69 67 3d 24 5f 5f 53 49 47 26 6f 76 72 3d 24 5f 5f 4f 56 52 26 62 72 6f 77 73 65 72 3d 24 5f 5f 42 52 4f 57 53 45 52 26 6c 61 62 65 6c 3d 25 73 26 61 75 78 3d 25 64 } //00 00  http://%s/v_install?sid=16045&start=1&guid=$__GUID&sig=$__SIG&ovr=$__OVR&browser=$__BROWSER&label=%s&aux=%d
		$a_00_4 = {7e 15 00 } //00 03 
	condition:
		any of ($a_*)
 
}