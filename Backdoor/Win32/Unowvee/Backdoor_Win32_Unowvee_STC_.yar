
rule Backdoor_Win32_Unowvee_STC_{
	meta:
		description = "Backdoor:Win32/Unowvee.STC!!Unowvee.STC,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_80_0 = {2f 74 69 6d 65 6f 75 74 2f 76 6f 69 70 2e 61 73 70 78 } ///timeout/voip.aspx  1
		$a_80_1 = {25 6c 73 3f 67 75 69 64 3d 25 6c 73 26 76 3d 25 6c 73 26 63 67 3d 25 6c 73 } //%ls?guid=%ls&v=%ls&cg=%ls  1
		$a_80_2 = {42 6f 74 56 65 72 73 69 6f 6e } //BotVersion  1
		$a_80_3 = {25 2e 32 64 3a 25 2e 32 64 20 25 2e 32 64 2d 25 5c 42 61 73 65 4e 61 6d 65 64 4f 62 6a 65 63 74 } //%.2d:%.2d %.2d-%\BaseNamedObject  1
		$a_80_4 = {25 41 50 50 44 41 54 41 25 5c 58 50 72 6f 66 69 6c 65 73 } //%APPDATA%\XProfiles  1
		$a_80_5 = {41 67 65 6e 74 5f 56 58 5f } //Agent_VX_  1
		$a_80_6 = {63 64 6e 2e 6e 76 62 63 6c 6f 75 64 2e 63 6f 6d } //cdn.nvbcloud.com  1
		$a_80_7 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //Select * From AntiVirusProduct  1
		$a_00_8 = {43 6f 6d 6d 61 6e 64 00 4e 45 57 00 54 41 53 4b } //1 潃浭湡d䕎W䅔䭓
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_00_8  & 1)*1) >=5
 
}