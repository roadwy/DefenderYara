
rule PWS_Win32_Kheagol_G{
	meta:
		description = "PWS:Win32/Kheagol.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 2e 70 68 70 } //1 data.php
		$a_01_1 = {61 3d 25 73 26 62 3d 25 73 26 63 3d 25 73 } //1 a=%s&b=%s&c=%s
		$a_01_2 = {68 e3 ca 1d 56 } //1
		$a_01_3 = {68 bd d9 e9 5d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}