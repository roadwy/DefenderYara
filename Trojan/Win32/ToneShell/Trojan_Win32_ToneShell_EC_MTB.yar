
rule Trojan_Win32_ToneShell_EC_MTB{
	meta:
		description = "Trojan:Win32/ToneShell.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {2f 43 20 73 63 68 74 61 73 6b 73 20 2f 46 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 46 46 57 61 6c 6c 70 61 70 65 72 45 6d 62 43 6f 72 65 20 2f 53 43 20 6d 69 6e 75 74 65 20 2f 4d 4f 20 36 20 2f 54 52 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 46 46 57 61 6c 6c 70 61 70 65 72 43 6f 72 65 5c 53 46 46 57 61 6c 6c 70 61 70 65 72 43 6f 72 65 2e 65 78 65 } //3 /C schtasks /F /Create /TN FFWallpaperEmbCore /SC minute /MO 6 /TR "C:\ProgramData\FFWallpaperCore\SFFWallpaperCore.exe
		$a_81_1 = {5a 61 63 6b 41 6c 6c 65 6e 2e 2e 2e 2e 2e 2e 74 65 63 68 79 74 65 61 63 68 6d 65 20 4f 6b } //1 ZackAllen......techyteachme Ok
		$a_81_2 = {53 74 61 72 74 2e 2e 2e 62 75 69 74 65 6e 67 65 62 69 65 64 65 6e } //1 Start...buitengebieden
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}