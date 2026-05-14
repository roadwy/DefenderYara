
rule Trojan_BAT_Loader_AMTB{
	meta:
		description = "Trojan:BAT/Loader!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {6e 65 6d 65 73 69 73 2e 65 78 65 } //nemesis.exe  1
		$a_80_1 = {47 3a 5c 6e 65 6d 65 73 69 73 5c 6e 65 6d 65 73 69 73 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6e 65 6d 65 73 69 73 2e 70 64 62 } //G:\nemesis\nemesis\obj\Release\nemesis.pdb  1
		$a_80_2 = {57 69 46 69 73 2e 74 78 74 } //WiFis.txt  1
		$a_80_3 = {49 6e 73 74 61 6c 6c 65 64 41 70 70 73 2e 74 78 74 } //InstalledApps.txt  1
		$a_80_4 = {6e 65 6d 65 73 69 73 5f 64 65 62 75 67 2e 74 78 74 } //nemesis_debug.txt  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}