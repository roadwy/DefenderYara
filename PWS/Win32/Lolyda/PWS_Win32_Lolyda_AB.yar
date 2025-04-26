
rule PWS_Win32_Lolyda_AB{
	meta:
		description = "PWS:Win32/Lolyda.AB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 08 80 f2 9a 88 11 41 4e 75 f4 } //1
		$a_01_1 = {8a 8c 05 00 ff ff ff 80 c1 0a 88 8c 05 00 fe ff ff 40 3b c7 7c ea } //1
		$a_00_2 = {26 7a 6f 6e 65 3d 25 73 26 73 65 72 76 65 72 3d 25 73 26 6e 61 6d 65 3d 25 73 26 70 61 73 73 3d 25 73 26 } //1 &zone=%s&server=%s&name=%s&pass=%s&
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}