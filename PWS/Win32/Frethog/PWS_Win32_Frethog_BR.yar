
rule PWS_Win32_Frethog_BR{
	meta:
		description = "PWS:Win32/Frethog.BR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 78 65 00 } //1
		$a_01_1 = {5f 5f 5f 5f 41 56 50 2e 52 6f 6f 74 00 } //1
		$a_03_2 = {83 c4 08 85 c0 74 ?? 6a 02 56 ff d7 8b f0 85 f6 75 d2 5f 8b c5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}