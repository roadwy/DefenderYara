
rule Trojan_Win32_AgentCrypt_SN_MTB{
	meta:
		description = "Trojan:Win32/AgentCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 1c 3b 8b 1b 81 e3 ff 00 00 00 29 c9 47 42 49 81 ff 90 01 02 00 00 75 05 bf 00 00 00 00 81 c2 90 01 04 c3 90 00 } //2
		$a_03_1 = {09 d2 31 1e 46 21 d2 39 c6 75 90 01 01 c3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_Win32_AgentCrypt_SN_MTB_2{
	meta:
		description = "Trojan:Win32/AgentCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 2f 2f 52 67 75 68 73 54 2f 61 63 63 65 70 74 2e 70 68 70 3f 61 3d } //1 GET ///RguhsT/accept.php?a=
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {4d 50 47 6f 6f 64 53 74 61 74 75 73 } //1 MPGoodStatus
		$a_01_3 = {6c 6f 63 61 6c 2e 66 6f 6f 2e 63 6f 6d } //1 local.foo.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}