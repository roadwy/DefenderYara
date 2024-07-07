
rule PWS_Win32_Steam_J{
	meta:
		description = "PWS:Win32/Steam.J,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 63 72 79 70 74 2e 70 68 70 3f 64 3d 31 } //1 /crypt.php?d=1
		$a_01_1 = {38 32 2e 31 34 36 2e 35 33 2e 31 31 } //1 82.146.53.11
		$a_01_2 = {5f 64 65 73 6b 74 6f 70 2e 63 6f 6d } //1 _desktop.com
		$a_01_3 = {64 6f 6d 61 69 6e 3d 25 73 26 63 6f 75 6e 74 3d 31 26 66 6e 61 6d 65 5f 31 3d 25 6c 73 26 66 63 6f 6e 74 5f 31 3d 25 73 } //1 domain=%s&count=1&fname_1=%ls&fcont_1=%s
		$a_01_4 = {5c 00 73 00 73 00 66 00 6e 00 2a 00 } //1 \ssfn*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}