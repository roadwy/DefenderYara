
rule Trojan_Win32_Claretore_M{
	meta:
		description = "Trojan:Win32/Claretore.M,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 72 63 3d 22 68 74 74 70 3a 2f 2f 25 73 2f 25 73 3f 25 73 3d 25 73 22 3e 3c } //1 src="http://%s/%s?%s=%s"><
		$a_00_1 = {24 6d 69 64 3d 25 73 26 75 69 64 3d 25 64 26 76 65 72 73 69 6f 6e 3d 25 73 } //1 $mid=%s&uid=%d&version=%s
		$a_01_2 = {77 76 3d 25 73 26 75 69 64 3d 25 64 26 6c 6e 67 3d 25 73 26 } //1 wv=%s&uid=%d&lng=%s&
		$a_01_3 = {72 65 70 6f 72 74 25 73 2e 25 73 2e 63 6f 6d } //1 report%s.%s.com
		$a_01_4 = {76 3d 73 70 66 31 20 61 20 6d 78 20 69 70 34 3a } //1 v=spf1 a mx ip4:
		$a_00_5 = {5c 5b 52 65 6c 65 61 73 65 2e 57 69 6e 33 32 5d 43 6c 69 63 6b 65 72 2e 70 64 62 } //2 \[Release.Win32]Clicker.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*2) >=3
 
}