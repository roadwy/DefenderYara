
rule Trojan_O97M_Donoff_RM_MTB{
	meta:
		description = "Trojan:O97M/Donoff.RM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 20 22 63 73 63 72 69 70 74 2e 65 78 65 20 25 61 70 70 64 61 74 61 25 5c 77 77 77 2e 74 78 74 20 2f 2f 45 3a 56 42 53 63 72 69 70 74 20 2f 2f 4e 6f 4c 6f 67 6f 20 22 20 2b 20 22 25 7e 66 30 22 20 2b 20 22 20 25 2a 22 2c 20 43 68 72 28 34 38 29 } //1 .Run "cscript.exe %appdata%\www.txt //E:VBScript //NoLogo " + "%~f0" + " %*", Chr(48)
		$a_03_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 90 02 3f 22 29 90 00 } //1
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c } //1 = Environ("USERPROFILE") & "\AppData\Roaming\
		$a_03_3 = {2b 20 22 77 77 77 2e 70 73 31 22 0d 0a 90 02 07 20 3d 20 90 02 05 20 2b 20 22 77 77 77 2e 74 78 74 22 0d 0a 90 02 05 20 3d 20 22 22 0d 0a 90 02 0a 20 3d 20 22 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 22 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}