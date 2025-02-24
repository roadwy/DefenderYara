
rule Trojan_BAT_LummaStealer_AYB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4a 75 73 74 41 42 61 63 6b 44 6f 6f 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 4a 75 73 74 41 42 61 63 6b 44 6f 6f 72 2e 70 64 62 } //2 JustABackDoor\obj\Debug\JustABackDoor.pdb
		$a_01_1 = {24 37 38 61 62 66 36 65 34 2d 61 34 64 61 2d 34 34 39 38 2d 38 65 66 66 2d 37 33 38 36 39 32 32 35 66 66 32 37 } //1 $78abf6e4-a4da-4498-8eff-73869225ff27
		$a_01_2 = {4a 75 73 74 41 42 61 63 6b 44 6f 6f 72 2e 45 78 65 63 75 74 6f 72 } //1 JustABackDoor.Executor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_LummaStealer_AYB_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {41 00 46 00 54 00 45 00 52 00 20 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 41 00 54 00 49 00 4f 00 4e 00 2c 00 20 00 53 00 4f 00 4c 00 41 00 52 00 41 00 20 00 57 00 49 00 4c 00 4c 00 20 00 41 00 50 00 50 00 45 00 41 00 52 00 20 00 4f 00 4e 00 20 00 59 00 4f 00 55 00 52 00 20 00 44 00 45 00 53 00 4b 00 54 00 4f 00 50 00 } //2 AFTER INSTALLATION, SOLARA WILL APPEAR ON YOUR DESKTOP
		$a_00_1 = {41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 } //1 Add-MpPreference -ExclusionPath
		$a_00_2 = {70 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2f 00 62 00 6c 00 61 00 2e 00 6a 00 70 00 67 00 } //1 properties/bla.jpg
		$a_00_3 = {64 00 65 00 62 00 75 00 67 00 2e 00 65 00 78 00 65 00 } //1 debug.exe
		$a_01_4 = {52 75 6e 50 6f 77 65 72 53 68 65 6c 6c 43 6f 6d 6d 61 6e 64 } //1 RunPowerShellCommand
		$a_01_5 = {64 65 62 75 67 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 debug.g.resources
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}