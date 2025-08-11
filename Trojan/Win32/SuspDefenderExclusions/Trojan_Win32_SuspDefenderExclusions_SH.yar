
rule Trojan_Win32_SuspDefenderExclusions_SH{
	meta:
		description = "Trojan:Win32/SuspDefenderExclusions.SH,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {26 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 64 6f 77 73 70 6f 77 65 72 73 68 65 6c 6c 5c } //& c:\windows\system32\windowspowershell\  2
		$a_80_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 63 6f 6d 6d 61 6e 64 } //powershell.exe -exec bypass -command  2
		$a_80_2 = {61 64 64 2d 6d 70 70 72 65 66 65 72 65 6e 63 65 } //add-mppreference  2
		$a_80_3 = {2d 65 78 63 6c 75 73 69 6f 6e 70 61 74 68 } //-exclusionpath  1
		$a_80_4 = {2d 65 78 63 6c 75 73 69 6f 6e 65 78 74 65 6e 73 69 6f 6e } //-exclusionextension  1
		$a_80_5 = {2d 65 78 63 6c 75 73 69 6f 6e 70 72 6f 63 65 73 73 } //-exclusionprocess  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=7
 
}