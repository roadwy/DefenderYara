
rule Adware_Win32_OpenSUpdater{
	meta:
		description = "Adware:Win32/OpenSUpdater,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {75 70 64 61 74 65 2e 75 70 64 61 74 65 72 2e 6f 6e 65 2f 69 6e 73 74 61 6c 6c 65 72 73 2f 4f 55 5f 55 70 64 61 74 65 72 2e 65 78 65 } //update.updater.one/installers/OU_Updater.exe  1
		$a_80_1 = {75 70 64 61 74 65 2e 75 70 64 61 74 65 72 2e 6f 6e 65 2f 75 70 64 61 74 65 2e 70 68 70 } //update.updater.one/update.php  1
		$a_80_2 = {64 3a 5c 43 6f 64 65 5c 4f 6e 65 55 70 64 61 74 65 72 5c 53 6f 75 72 63 65 5c 4f 6e 65 55 70 64 61 74 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4f 6e 65 55 70 64 61 74 65 72 2e 70 64 62 } //d:\Code\OneUpdater\Source\OneUpdater\obj\Release\OneUpdater.pdb  1
		$a_80_3 = {41 43 54 49 56 41 54 45 } //ACTIVATE  1
		$a_80_4 = {6f 75 2d 76 65 72 73 69 6f 6e 2e 70 68 70 } //ou-version.php  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}