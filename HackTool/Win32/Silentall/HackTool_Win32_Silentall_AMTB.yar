
rule HackTool_Win32_Silentall_AMTB{
	meta:
		description = "HackTool:Win32/Silentall!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 6f 6c 69 64 53 68 61 72 65 2e 4e 65 74 20 55 6e 61 74 74 65 6e 64 65 64 20 49 6e 73 74 61 6c 6c 65 72 } //SolidShare.Net Unattended Installer  1
		$a_80_1 = {23 72 65 71 75 69 72 65 61 64 6d 69 6e } //#requireadmin  1
		$a_80_2 = {43 43 6c 65 61 6e 65 72 20 54 65 63 68 6e 69 63 69 61 6e 20 45 64 69 74 69 6f 6e } //CCleaner Technician Edition  1
		$a_80_3 = {53 6f 6c 69 64 53 68 61 72 65 20 54 45 41 4d } //SolidShare TEAM  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}