
rule Trojan_Win32_Lopock_A{
	meta:
		description = "Trojan:Win32/Lopock.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 57 69 6e 6c 6f 63 6b 65 72 5c 52 65 6c 65 61 73 65 5c 57 69 6e 6c 6f 63 6b 65 72 2e 70 64 62 } //1 :\Winlocker\Release\Winlocker.pdb
		$a_01_1 = {63 6d 64 3d 69 6e 73 74 61 6c 6c 26 75 69 64 3d 25 73 26 6f 73 3d 25 73 26 76 65 72 73 69 6f 6e 3d 25 73 } //1 cmd=install&uid=%s&os=%s&version=%s
		$a_01_2 = {6a 04 8d 45 f4 50 6a 06 57 c7 45 f4 c0 27 09 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}