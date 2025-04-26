
rule TrojanDownloader_O97M_Donoff_SMC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SMC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 77 42 54 41 48 6b 41 55 77 42 55 41 47 55 41 62 51 41 75 41 48 51 41 5a 51 42 59 41 48 51 41 4c 67 42 6c 41 47 34 41 51 77 42 76 41 47 51 41 61 51 42 75 41 47 63 41 58 51 41 36 41 44 6f 41 56 51 42 4f 41 47 6b 41 59 77 42 76 41 45 51 41 5a 51 41 75 41 45 63 41 5a 51 42 30 41 48 4d 41 64 41 42 53 41 47 6b 41 54 67 42 6e 41 43 67 41 57 77 42 7a 41 46 6b 41 63 77 42 55 41 47 } //1 WwBTAHkAUwBUAGUAbQAuAHQAZQBYAHQALgBlAG4AQwBvAGQAaQBuAGcAXQA6ADoAVQBOAGkAYwBvAEQAZQAuAEcAZQB0AHMAdABSAGkATgBnACgAWwBzAFkAcwBUAG
		$a_01_1 = {67 68 67 66 20 3d 20 22 68 6a 20 75 79 6a 75 79 20 74 68 79 74 79 20 75 79 6a 79 75 6a 74 79 74 } //1 ghgf = "hj uyjuy thyty uyjyujtyt
		$a_01_2 = {66 67 67 68 6a 68 67 20 3d 20 22 73 64 61 64 20 64 73 61 66 68 20 64 73 61 75 69 66 20 64 61 73 66 } //1 fgghjhg = "sdad dsafh dsauif dasf
		$a_01_3 = {6a 61 70 2e 52 75 6e 28 } //1 jap.Run(
		$a_01_4 = {46 42 2e 49 79 } //1 FB.Iy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}