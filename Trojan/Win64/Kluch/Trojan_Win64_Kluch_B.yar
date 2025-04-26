
rule Trojan_Win64_Kluch_B{
	meta:
		description = "Trojan:Win64/Kluch.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c } //1 WLEventStartShell
		$a_01_1 = {5a 6d 63 47 64 69 43 6f 6e 76 65 72 74 4d 65 74 61 46 69 6c 65 50 69 63 74 } //1 ZmcGdiConvertMetaFilePict
		$a_01_2 = {7e 43 48 74 74 70 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 0a 00 } //1
		$a_01_3 = {62 50 72 6f 78 79 45 6e 61 62 6c 65 3d 25 64 2c 6d 5f 50 52 4f 58 59 5f 48 4f 53 54 3d 25 73 2c 6d 5f 50 52 4f 58 59 5f 55 53 45 52 3d 25 73 } //1 bProxyEnable=%d,m_PROXY_HOST=%s,m_PROXY_USER=%s
		$a_01_4 = {35 66 75 7a 61 34 35 26 4c 56 3d 32 30 30 37 37 26 56 3d } //1 5fuza45&LV=20077&V=
		$a_01_5 = {41 39 35 73 38 55 5f 30 4f 39 49 37 79 } //1 A95s8U_0O9I7y
		$a_01_6 = {43 72 65 61 74 65 48 54 54 50 43 6f 6e 6e 65 63 74 20 68 57 69 6e 69 6e 65 74 3d 25 70 2c 41 64 64 72 3d 25 70 2c 68 4f 70 65 6e 48 61 6e 64 6c 65 3d 25 70 } //1 CreateHTTPConnect hWininet=%p,Addr=%p,hOpenHandle=%p
		$a_01_7 = {41 c6 43 e1 e9 41 c6 43 e2 7c 41 c6 43 e3 bf 41 c6 43 e4 4f 41 c6 43 e5 7a 41 c6 43 e6 6e 41 c6 43 e7 8f } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*2) >=8
 
}