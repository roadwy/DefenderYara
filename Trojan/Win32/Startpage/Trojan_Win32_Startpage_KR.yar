
rule Trojan_Win32_Startpage_KR{
	meta:
		description = "Trojan:Win32/Startpage.KR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {60 9c 8b ca e8 00 00 00 00 5b 8d 55 bc b8 90 01 04 52 ff d0 89 45 fc 9d 61 80 7d fc 00 74 06 0f b6 45 fc eb 90 00 } //1
		$a_01_1 = {8a 04 16 8a c8 c0 e9 04 c0 e0 04 0a c8 80 7d ff 00 75 04 c6 45 ff 01 8a 45 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Startpage_KR_2{
	meta:
		description = "Trojan:Win32/Startpage.KR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 52 74 6b 53 59 55 64 70 2e 65 78 65 20 66 69 6c 6c 64 65 6c 65 74 65 20 20 } //1 \RtkSYUdp.exe filldelete  
		$a_01_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 00 00 5c 5c 2e 5c 53 4d 41 52 54 56 53 44 00 } //1
		$a_01_2 = {53 74 61 72 74 20 50 61 67 65 22 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 65 31 32 33 2e 63 6f 6d } //1 Start Page"="http://www.hae123.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}