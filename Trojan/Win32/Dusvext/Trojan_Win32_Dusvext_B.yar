
rule Trojan_Win32_Dusvext_B{
	meta:
		description = "Trojan:Win32/Dusvext.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {5d 26 63 6f 75 6e 74 72 79 3d } //1 ]&country=
		$a_01_1 = {26 63 6d 70 6e 61 6d 65 3d } //1 &cmpname=
		$a_01_2 = {61 64 64 75 73 65 72 2e 70 68 70 3f 75 69 64 3d } //1 adduser.php?uid=
		$a_01_3 = {70 6f 73 74 65 72 2e 70 68 70 3f 75 69 64 3d } //1 poster.php?uid=
		$a_01_4 = {56 65 72 74 65 78 4e 65 74 } //1 VertexNet
		$a_01_5 = {67 65 74 6b 6c 6f 67 73 } //1 getklogs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}