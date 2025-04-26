
rule Worm_BAT_Roxin_A{
	meta:
		description = "Worm:BAT/Roxin.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {5c 5c 2e 5c 72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 3a 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //\\.\root\SecurityCenter:AntivirusProduct  1
		$a_00_1 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_00_2 = {57 6f 72 6d 53 65 72 76 69 63 65 } //1 WormService
		$a_80_3 = {6f 6e 41 63 63 65 73 73 53 63 61 6e 6e 69 6e 67 45 6e 61 62 6c 65 64 } //onAccessScanningEnabled  1
		$a_80_4 = {43 4d 44 2e 45 58 45 20 2f 64 20 2f 63 20 65 63 68 6f 20 6f 70 65 6e } //CMD.EXE /d /c echo open  1
		$a_80_5 = {26 64 65 6c 20 2a 2e 2a } //&del *.*  1
		$a_80_6 = {73 6f 66 74 2e 69 6e 74 6f 34 2e 69 6e 66 6f } //soft.into4.info  1
		$a_80_7 = {2f 69 74 2e 61 73 70 3f 69 6e 74 54 69 6d 65 73 3d } ///it.asp?intTimes=  1
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=7
 
}