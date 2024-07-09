
rule PWS_Win32_QQpass_CA{
	meta:
		description = "PWS:Win32/QQpass.CA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3d 25 73 26 68 3d 25 64 26 76 3d 25 73 26 65 70 3d 25 73 26 64 62 3d 25 64 00 } //1
		$a_01_1 = {5c 44 65 76 69 63 65 5c 4e 50 46 5f 00 } //1
		$a_03_2 = {72 02 5d c3 5d c3 55 8b ec 83 05 ?? ?? ?? 00 01 72 02 5d c3 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}