
rule Trojan_Linux_Nahooli_A{
	meta:
		description = "Trojan:Linux/Nahooli.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {3d 20 55 73 65 72 46 6f 72 6d 31 2e 53 63 72 69 70 74 43 6f 6e 74 72 6f 6c 31 [0-0e] 2e 4c 61 6e 67 75 61 67 65 20 3d 20 22 56 42 53 22 20 2b 20 22 63 72 69 70 74 22 [0-11] 3d 20 22 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 22 [0-0e] 3d 20 22 50 61 72 61 67 72 61 70 68 73 22 } //1
		$a_00_1 = {3d 20 22 65 78 65 22 } //1 = "exe"
		$a_02_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 [0-07] 43 68 44 72 69 76 65 20 28 [0-07] 29 [0-07] 43 68 44 69 72 20 28 [0-07] 29 [0-14] 3d 20 46 72 65 65 46 69 6c 65 28 29 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}