
rule Trojan_Win32_RedLine_DX_MTB{
	meta:
		description = "Trojan:Win32/RedLine.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 89 6c 24 10 8d 6c 24 10 2b e0 53 56 57 a1 04 73 4d 00 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 64 a3 } //1
		$a_81_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65 } //1 C:\Windows\Microsoft.NET\Framework\v4.0.30319\AppLaunch.exe
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}