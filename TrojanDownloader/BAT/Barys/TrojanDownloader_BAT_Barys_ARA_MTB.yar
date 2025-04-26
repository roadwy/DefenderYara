
rule TrojanDownloader_BAT_Barys_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Barys.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 46 37 45 33 43 41 39 2e 72 65 73 6f 75 72 63 65 73 } //2 2F7E3CA9.resources
		$a_01_1 = {24 31 39 66 31 33 61 31 36 2d 39 39 63 36 2d 34 33 39 64 2d 61 61 38 65 2d 65 34 30 34 65 35 66 32 34 34 37 61 } //2 $19f13a16-99c6-439d-aa8e-e404e5f2447a
		$a_80_2 = {61 48 52 30 63 48 4d 36 4c 79 39 68 64 58 52 6f 4c 6e 4e 74 59 6e 4e 77 62 32 39 6d 5a 58 49 75 65 48 6c 36 4c 77 3d 3d } //aHR0cHM6Ly9hdXRoLnNtYnNwb29mZXIueHl6Lw==  2
		$a_80_3 = {64 65 6c 20 2f 73 20 2f 66 20 2f 71 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 50 72 65 66 65 74 63 68 } //del /s /f /q C:\Windows\Prefetch  2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}