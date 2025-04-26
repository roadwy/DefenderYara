
rule Trojan_Win32_Proscks_C_dll{
	meta:
		description = "Trojan:Win32/Proscks.C!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_00_1 = {25 57 69 6e 44 69 72 25 5c 53 79 73 74 65 6d 33 32 5c 44 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 %WinDir%\System32\Drivers\etc\hosts
		$a_00_2 = {43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 00 00 25 00 25 00 74 00 65 00 6d 00 70 00 25 00 25 00 5c 00 25 00 30 00 38 00 64 00 25 00 30 00 38 00 64 00 } //1
		$a_00_3 = {25 73 26 61 64 5f 69 64 3d 25 73 26 61 64 5f 68 6f 75 72 3d 25 73 26 61 64 5f 76 69 65 77 6e 75 6d 3d 25 73 26 61 64 5f 63 6c 69 63 6b 6e 75 6d 3d 25 73 26 76 65 72 3d 25 73 } //1 %s&ad_id=%s&ad_hour=%s&ad_viewnum=%s&ad_clicknum=%s&ver=%s
		$a_00_4 = {45 78 70 6f 72 74 00 58 6f 72 44 61 74 61 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}