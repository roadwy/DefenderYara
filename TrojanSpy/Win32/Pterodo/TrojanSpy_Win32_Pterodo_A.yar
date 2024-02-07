
rule TrojanSpy_Win32_Pterodo_A{
	meta:
		description = "TrojanSpy:Win32/Pterodo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 53 42 67 72 61 62 62 65 72 2e 64 6c 6c 00 53 74 61 72 74 42 61 63 6b 75 70 } //01 00  单杂慲扢牥搮汬匀慴瑲慂正灵
		$a_01_1 = {5f 00 5f 00 57 00 73 00 6e 00 75 00 73 00 62 00 37 00 33 00 5f 00 5f 00 } //00 00  __Wsnusb73__
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Pterodo_A_2{
	meta:
		description = "TrojanSpy:Win32/Pterodo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 53 42 67 72 61 62 62 65 72 2e 64 6c 6c } //01 00  USBgrabber.dll
		$a_01_1 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 63 6f 6d 70 6e 61 6d 65 22 } //01 00  Content-Disposition: form-data; name="compname"
		$a_01_2 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 77 22 } //00 00  Content-Disposition: form-data; name="w"
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}