
rule TrojanDownloader_O97M_EncDoc_PAAE_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 5f 6e 61 6d 65 3d 22 6d 6f 64 75 6c 65 31 22 73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 73 65 74 6f 73 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 72 6e 78 77 75 64 74 75 69 28 73 74 72 72 65 76 65 72 73 65 } //1 b_name="module1"subauto_open()setos=createobject(rnxwudtui(strreverse
		$a_01_1 = {3a 73 70 74 74 68 61 74 68 73 6d 5c 2e 2e 5c 63 6c 61 63 5c 32 33 6d 65 74 73 79 73 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29 2b } //1 :sptthathsm\..\clac\23metsys\swodniw\:c")+
		$a_01_2 = {29 29 2b 31 29 2c 31 29 29 72 6e 78 77 75 64 74 75 69 3d 72 6e 78 77 75 64 74 75 69 26 63 68 72 24 28 61 73 63 28 6d 69 64 24 28 6d 64 65 64 6e 72 79 73 6b 2c 63 7a 62 32 66 69 67 61 6e 2c 31 29 29 78 6f 72 68 78 72 6b 77 74 65 6c 75 29 6e 65 78 74 63 } //1 ))+1),1))rnxwudtui=rnxwudtui&chr$(asc(mid$(mdednrysk,czb2figan,1))xorhxrkwtelu)nextc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}