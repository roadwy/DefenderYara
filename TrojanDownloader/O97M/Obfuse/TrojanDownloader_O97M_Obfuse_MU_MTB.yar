
rule TrojanDownloader_O97M_Obfuse_MU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-35] 28 43 53 74 72 28 4c 65 6e 28 } //1
		$a_01_1 = {2b 20 22 77 31 33 39 69 31 33 39 6e 31 33 39 6d 67 31 33 39 6d 74 73 31 33 39 3a 57 69 31 33 39 6e 33 32 31 33 39 5f 50 72 31 33 39 6f 63 65 31 33 39 73 73 22 29 29 } //1 + "w139i139n139mg139mts139:Wi139n32139_Pr139oce139ss"))
		$a_01_2 = {22 77 36 36 69 36 36 6e 36 36 6d 67 36 36 6d 74 73 36 36 3a 57 69 36 36 6e 33 32 36 36 5f 50 72 36 36 6f 63 65 36 36 73 73 22 29 29 } //1 "w66i66n66mg66mts66:Wi66n3266_Pr66oce66ss"))
		$a_01_3 = {2b 20 22 77 31 35 36 69 31 35 36 6e 31 35 36 6d 67 31 35 36 6d 74 73 31 35 36 3a 57 69 31 35 36 6e 33 32 31 35 36 5f 50 72 31 35 36 6f 63 65 31 35 36 73 73 22 29 29 } //1 + "w156i156n156mg156mts156:Wi156n32156_Pr156oce156ss"))
		$a_03_4 = {2e 43 72 65 61 74 65 28 [0-38] 2c } //1
		$a_03_5 = {3d 20 52 65 70 6c 61 63 65 28 [0-35] 2c } //1
		$a_01_6 = {4d 53 46 6f 72 6d 73 2c 20 54 65 78 74 42 6f 78 22 } //1 MSForms, TextBox"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}