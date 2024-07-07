
rule Trojan_Win32_Claretore_I{
	meta:
		description = "Trojan:Win32/Claretore.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {24 6d 69 64 3d 25 53 26 75 69 64 3d 25 64 26 76 65 72 73 69 6f 6e 3d 25 73 24 } //1 $mid=%S&uid=%d&version=%s$
		$a_00_1 = {76 3d 73 70 66 31 20 61 20 6d 78 20 69 70 34 } //1 v=spf1 a mx ip4
		$a_01_2 = {0f 31 52 50 68 94 e3 40 00 8d 85 fc fb ff ff 68 04 01 00 00 50 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}