
rule TrojanDownloader_Win32_Wxpse{
	meta:
		description = "TrojanDownloader:Win32/Wxpse,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 62 33 2e 39 39 38 66 6c 61 73 68 2e 63 6e 2f 64 6f 77 6e 6c 6f 61 64 2f } //5 http://b3.998flash.cn/download/
		$a_00_1 = {77 78 70 53 65 74 75 70 00 00 } //5
		$a_02_2 = {61 72 75 6e 2e 72 65 67 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 52 65 67 65 64 69 74 2e 65 78 65 20 2f 73 20 } //1
		$a_00_3 = {5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5d } //1 [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}