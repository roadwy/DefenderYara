
rule TrojanDownloader_Win32_Wolfic_D{
	meta:
		description = "TrojanDownloader:Win32/Wolfic.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {35 00 36 00 37 00 36 00 32 00 65 00 62 00 39 00 2d 00 34 00 31 00 31 00 63 00 2d 00 34 00 38 00 34 00 32 00 2d 00 39 00 35 00 33 00 30 00 2d 00 39 00 39 00 32 00 32 00 63 00 34 00 36 00 62 00 61 00 32 00 64 00 } //2 56762eb9-411c-4842-9530-9922c46ba2d
		$a_80_1 = {48 69 6a 61 63 6b 69 6e 67 4c 69 62 2e 64 6c 6c } //HijackingLib.dll  2
		$a_80_2 = {5c 57 53 4f 43 4b 33 32 2e 64 6c 6c 2e 45 6e 75 6d 50 72 6f 74 6f 63 6f 6c } //\WSOCK32.dll.EnumProtocol  1
		$a_80_3 = {5c 57 53 4f 43 4b 33 32 2e 64 6c 6c 2e 47 65 74 41 63 63 65 70 74 45 78 53 6f 63 6b 61 64 64 72 73 } //\WSOCK32.dll.GetAcceptExSockaddrs  1
	condition:
		((#a_00_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}