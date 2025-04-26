
rule HackTool_Win32_Mimikatz_D_{
	meta:
		description = "HackTool:Win32/Mimikatz.D!!Mikatz.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 0e 00 00 "
		
	strings :
		$a_00_0 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 password
		$a_00_1 = {6b 00 69 00 77 00 69 00 5f 00 6d 00 73 00 76 00 31 00 5f 00 30 00 5f 00 63 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 } //1 kiwi_msv1_0_credentials
		$a_00_2 = {6d 69 6d 69 6b 61 74 7a } //1 mimikatz
		$a_00_3 = {73 61 6d 65 6e 75 6d 65 72 61 74 65 64 6f 6d 61 69 6e 73 69 6e 73 61 6d 73 65 72 76 65 72 } //1 samenumeratedomainsinsamserver
		$a_00_4 = {70 6f 77 65 72 73 68 65 6c 6c 5f 72 65 66 6c 65 63 74 69 76 65 5f 6d 69 6d 69 6b 61 74 7a } //1 powershell_reflective_mimikatz
		$a_00_5 = {70 6f 77 65 72 6b 61 74 7a 2e 64 6c 6c } //1 powerkatz.dll
		$a_00_6 = {5f 4e 65 74 53 65 72 76 65 72 54 72 75 73 74 50 61 73 73 77 6f 72 64 73 47 65 74 } //1 _NetServerTrustPasswordsGet
		$a_80_7 = {77 69 6e 64 6f 77 73 5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 } //windows\kevlar-api\kevlarsigs  -20
		$a_80_8 = {5c 6b 65 76 6c 61 72 2d 61 70 69 5c 6b 65 76 6c 61 72 73 69 67 73 36 34 5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 48 49 50 48 61 6e 64 6c 65 72 73 36 34 2e 70 64 62 } //\kevlar-api\kevlarsigs64\x64\release\HIPHandlers64.pdb  -20
		$a_80_9 = {5c 6d 63 61 66 65 65 5c 68 6f 73 74 20 69 6e 74 72 75 73 69 6f 6e 20 70 72 65 76 65 6e 74 69 6f 6e 5c 68 69 70 } //\mcafee\host intrusion prevention\hip  -20
		$a_80_10 = {5c 73 64 6b 2e 70 72 6f 74 65 63 74 6f 72 5c 6d 69 6e 6f 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 36 34 2e 70 64 62 } //\sdk.protector\minor\x64\Release\Protector64.pdb  -20
		$a_80_11 = {6d 6f 72 70 68 69 73 65 63 5f 64 6c 6c 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_dll_version_s  -20
		$a_80_12 = {6d 6f 72 70 68 69 73 65 63 5f 70 72 6f 64 75 63 74 5f 76 65 72 73 69 6f 6e 5f 73 } //morphisec_product_version_s  -20
		$a_80_13 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 6f 72 53 65 72 76 69 63 65 36 34 2e 70 64 62 } //\x64\Release\ProtectorService64.pdb  -20
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_80_7  & 1)*-20+(#a_80_8  & 1)*-20+(#a_80_9  & 1)*-20+(#a_80_10  & 1)*-20+(#a_80_11  & 1)*-20+(#a_80_12  & 1)*-20+(#a_80_13  & 1)*-20) >=5
 
}