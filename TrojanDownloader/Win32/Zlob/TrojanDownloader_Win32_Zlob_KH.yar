
rule TrojanDownloader_Win32_Zlob_KH{
	meta:
		description = "TrojanDownloader:Win32/Zlob.KH,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {36 38 36 30 41 34 34 42 2d 35 44 33 45 2d 34 33 33 44 2d 41 37 42 35 2d 44 35 31 37 46 38 31 30 44 30 45 37 } //6860A44B-5D3E-433D-A7B5-D517F810D0E7  1
		$a_80_1 = {64 6e 73 6d 73 65 72 72 6f 72 73 2e 63 6f 6d } //dnsmserrors.com  1
		$a_00_2 = {68 62 76 74 2e 64 6c 6c } //1 hbvt.dll
		$a_00_3 = {73 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 65 00 73 00 } //1 sn.com/res
		$a_00_4 = {73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 69 00 6c 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 70 00 68 00 70 00 3f 00 71 00 71 00 3d 00 25 00 73 00 } //1 securitypills.com/search.php?qq=%s
		$a_00_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_00_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}