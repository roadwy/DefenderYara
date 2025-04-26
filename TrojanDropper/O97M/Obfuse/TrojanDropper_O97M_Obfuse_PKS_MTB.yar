
rule TrojanDropper_O97M_Obfuse_PKS_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.PKS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 75 70 64 61 74 65 2e 6a 73 } //1 C:\Users\Public\update.js
		$a_03_1 = {77 69 6e 6d 67 6d 74 73 3a 27 2c 27 43 3a 5c [0-05] 50 72 6f 67 72 61 6d 44 61 74 61 5c [0-05] 64 64 6f 6e 64 2e 63 6f 6d } //1
		$a_01_2 = {6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 66 69 6c 65 2f 76 77 74 32 75 38 37 6a 66 7a 70 62 30 66 34 2f 33 2e 68 74 6d 2f 66 69 6c 65 } //1 mediafire.com/file/vwt2u87jfzpb0f4/3.htm/file
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 [0-0a] 2c 20 22 [0-05] 22 2c 20 22 [0-03] 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}