
rule PWS_Win32_DNFOnline_A{
	meta:
		description = "PWS:Win32/DNFOnline.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {68 b2 27 00 00 53 68 01 02 00 00 ff 35 90 01 02 40 00 ff 15 90 01 02 40 00 6a 0a 90 00 } //1
		$a_03_1 = {33 f6 56 ff 35 90 01 02 40 00 ff 15 90 01 02 40 00 6a 03 56 56 56 56 6a 01 ff 35 90 01 02 40 00 ff 15 90 00 } //1
		$a_00_2 = {64 69 6d 65 70 61 73 73 6d 65 6d } //1 dimepassmem
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}