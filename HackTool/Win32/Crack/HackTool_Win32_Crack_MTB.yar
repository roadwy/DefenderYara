
rule HackTool_Win32_Crack_MTB{
	meta:
		description = "HackTool:Win32/Crack!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {52 61 72 45 78 74 49 6e 73 74 61 6c 6c 65 72 2e 70 64 62 } //RarExtInstaller.pdb  2
		$a_80_1 = {43 3a 5c 4e 65 76 65 72 53 68 6f 77 2e 74 78 74 } //C:\NeverShow.txt  1
		$a_80_2 = {4f 6e 43 6c 69 63 6b } //OnClick  1
		$a_80_3 = {72 65 70 61 63 6b 73 2e 64 64 6e 73 2e 6e 65 74 } //repacks.ddns.net  1
		$a_80_4 = {72 65 70 61 63 6b 2e 6d 65 } //repack.me  1
		$a_80_5 = {41 63 74 69 76 61 74 69 6f 6e } //Activation  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule HackTool_Win32_Crack_MTB_2{
	meta:
		description = "HackTool:Win32/Crack!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {63 72 61 63 6b 65 72 } //cracker  1
		$a_80_1 = {2a 53 54 41 52 54 20 50 41 54 43 48 49 4e 47 2a } //*START PATCHING*  1
		$a_80_2 = {4f 46 46 53 45 54 20 50 41 54 43 48 } //OFFSET PATCH  1
		$a_80_3 = {53 45 41 52 43 48 20 26 20 52 45 50 4c 41 43 45 20 50 41 54 43 48 } //SEARCH & REPLACE PATCH  1
		$a_80_4 = {50 41 54 43 48 49 4e 47 20 44 4f 4e 45 } //PATCHING DONE  1
		$a_80_5 = {50 61 74 63 68 74 61 72 67 65 74 } //Patchtarget  1
		$a_80_6 = {52 45 47 49 53 54 52 59 20 50 41 54 43 48 } //REGISTRY PATCH  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule HackTool_Win32_Crack_MTB_3{
	meta:
		description = "HackTool:Win32/Crack!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {72 65 70 61 63 6b 73 2e 64 64 6e 73 2e 6e 65 74 } //repacks.ddns.net  1
		$a_80_1 = {73 3a 5c 49 44 4d 5f 70 72 6f 6a 65 63 74 73 5c 49 44 4d 49 45 43 43 32 5c 36 34 62 69 74 5c 52 65 6c 65 61 73 65 4d 69 6e 44 65 70 65 6e 64 65 6e 63 79 5c 49 44 4d 49 45 43 43 36 34 2e 70 64 62 } //s:\IDM_projects\IDMIECC2\64bit\ReleaseMinDependency\IDMIECC64.pdb  1
		$a_80_2 = {41 63 74 69 76 61 74 65 2e 63 6d 64 } //Activate.cmd  1
		$a_80_3 = {50 75 72 65 46 6c 61 74 2e 74 62 69 } //PureFlat.tbi  1
		$a_80_4 = {54 6f 6e 65 6b 20 49 6e 63 } //Tonek Inc  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}