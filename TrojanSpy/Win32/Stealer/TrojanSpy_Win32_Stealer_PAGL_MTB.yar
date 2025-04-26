
rule TrojanSpy_Win32_Stealer_PAGL_MTB{
	meta:
		description = "TrojanSpy:Win32/Stealer.PAGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {75 00 73 00 65 00 72 00 3d 00 25 00 64 00 26 00 69 00 64 00 3d 00 25 00 64 00 26 00 69 00 70 00 3d 00 25 00 73 00 26 00 6d 00 61 00 63 00 3d 00 25 00 73 00 26 00 73 00 79 00 73 00 69 00 6e 00 66 00 6f 00 3d 00 25 00 73 00 26 00 75 00 72 00 6c 00 3d 00 } //1 user=%d&id=%d&ip=%s&mac=%s&sysinfo=%s&url=
		$a_00_1 = {2f 00 73 00 74 00 61 00 74 00 2f 00 74 00 65 00 73 00 74 00 6c 00 73 00 } //1 /stat/testls
		$a_00_2 = {53 00 70 00 79 00 44 00 6c 00 6c 00 } //2 SpyDll
		$a_01_3 = {5c 48 69 6a 61 63 6b 5c 52 65 6c 65 61 73 65 5c 53 50 49 46 69 6c 74 65 72 2e 70 64 62 } //2 \Hijack\Release\SPIFilter.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}