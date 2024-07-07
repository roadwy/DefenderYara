
rule PWS_Win32_Vidar_YB_MTB{
	meta:
		description = "PWS:Win32/Vidar.YB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 00 69 00 64 00 61 00 72 00 2e 00 63 00 70 00 70 00 } //1 Vidar.cpp
		$a_01_1 = {73 00 65 00 61 00 72 00 63 00 68 00 53 00 74 00 72 00 69 00 6e 00 67 00 20 00 21 00 3d 00 20 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 searchString != replaceString
		$a_01_2 = {68 74 74 70 3a 2f 2f 69 70 2d 61 70 69 2e 63 6f 6d 2f } //1 http://ip-api.com/
		$a_01_3 = {2a 77 61 6c 6c 65 74 2a 2e 64 61 74 } //1 *wallet*.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}