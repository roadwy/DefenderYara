
rule TrojanProxy_Win32_Dosenjo_B{
	meta:
		description = "TrojanProxy:Win32/Dosenjo.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {3f 61 63 74 69 6f 6e 3d 73 65 72 70 26 77 3d 25 73 26 69 64 3d 25 73 26 61 63 63 3d 25 64 26 6e 63 3d 25 73 } //1 ?action=serp&w=%s&id=%s&acc=%d&nc=%s
		$a_01_1 = {25 73 26 69 70 3d 25 73 26 6d 6f 64 65 3d 25 73 26 64 6c 6c 3d 25 64 } //1 %s&ip=%s&mode=%s&dll=%d
		$a_01_2 = {3f 63 61 63 68 69 6e 67 44 65 6e 79 3d } //1 ?cachingDeny=
		$a_01_3 = {63 73 72 73 73 25 73 2e 64 6c 6c } //1 csrss%s.dll
		$a_01_4 = {31 31 30 3a 54 43 50 3a 2a 3a 45 6e 61 62 6c 65 64 3a 73 76 63 68 6f 73 74 } //1 110:TCP:*:Enabled:svchost
		$a_01_5 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 20 43 6f 6d 70 61 74 69 62 6c 65 20 50 70 63 20 4c 69 6e 6b 65 72 } //1 User-Agent: Mozilla Compatible Ppc Linker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}