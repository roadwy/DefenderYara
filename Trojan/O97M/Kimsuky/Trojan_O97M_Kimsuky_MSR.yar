
rule Trojan_O97M_Kimsuky_MSR{
	meta:
		description = "Trojan:O97M/Kimsuky!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 6e 6f 4c 6f 67 6f 20 24 73 3d 5b 53 79 73 74 65 6d 2e 49 4f 2e 46 69 6c 65 5d 3a 3a 52 65 61 64 41 6c 6c 54 65 78 74 28 27 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-0a] 2e 74 78 74 27 29 3b 69 65 78 20 24 73 } //1
		$a_01_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_01_3 = {2e 52 75 6e 20 64 31 2c 20 4c 65 66 74 } //1 .Run d1, Left
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}