
rule TrojanSpy_Win32_Wavrat_A{
	meta:
		description = "TrojanSpy:Win32/Wavrat.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 00 77 00 73 00 3a 00 2f 00 2f 00 25 00 77 00 73 00 3a 00 25 00 64 00 25 00 77 00 73 00 } //1 %ws://%ws:%d%ws
		$a_01_1 = {63 00 64 00 6e 00 2e 00 62 00 69 00 74 00 6e 00 61 00 6d 00 69 00 2e 00 63 00 6f 00 6d 00 } //1 cdn.bitnami.com
		$a_01_2 = {2e 00 63 00 6c 00 6f 00 75 00 64 00 66 00 72 00 6f 00 6e 00 74 00 2e 00 6e 00 65 00 74 00 } //1 .cloudfront.net
		$a_01_3 = {2f 61 74 6f 6d 73 2f 61 75 74 68 5f 78 58 78 2f } //1 /atoms/auth_xXx/
		$a_01_4 = {75 73 65 72 6e 61 6d 65 3d 25 73 } //1 username=%s
		$a_01_5 = {2f 61 74 6f 6d 73 2f 25 73 2f 69 6e 66 6f } //1 /atoms/%s/info
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}