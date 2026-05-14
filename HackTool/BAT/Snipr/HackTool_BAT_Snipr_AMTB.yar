
rule HackTool_BAT_Snipr_AMTB{
	meta:
		description = "HackTool:BAT/Snipr!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {57 65 62 2d 49 6e 73 74 61 6c 6c 65 72 20 66 6f 72 20 53 4e 49 50 52 } //Web-Installer for SNIPR  1
		$a_80_1 = {43 3a 5c 55 73 65 72 73 5c 50 52 41 47 4d 41 5c 44 6f 63 75 6d 65 6e 74 73 5c 50 72 6f 6a 65 63 74 73 5c 53 4e 49 50 52 2d 49 6e 73 74 61 6c 6c 65 72 5c 53 4e 49 50 52 2d 49 6e 73 74 61 6c 6c 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 4e 49 50 52 2d 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //C:\Users\PRAGMA\Documents\Projects\SNIPR-Installer\SNIPR-Installer\obj\Release\SNIPR-Installer.pdb  2
		$a_80_2 = {53 4e 49 50 52 2e 6c 6e 6b } //SNIPR.lnk  1
		$a_80_3 = {53 4e 49 50 52 2e 65 78 65 } //SNIPR.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}