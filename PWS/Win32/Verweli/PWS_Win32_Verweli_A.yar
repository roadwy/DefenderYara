
rule PWS_Win32_Verweli_A{
	meta:
		description = "PWS:Win32/Verweli.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 42 4f 4d 53 55 38 74 34 54 71 2b 2f 42 6d 55 61 6a 39 47 6c 77 3d 3d } //1 bBOMSU8t4Tq+/BmUaj9Glw==
		$a_01_1 = {36 55 66 2f 52 65 67 46 70 48 37 7a 47 44 7a 78 48 33 74 54 36 41 3d 3d } //1 6Uf/RegFpH7zGDzxH3tT6A==
		$a_01_2 = {56 41 4e 65 2b 6c 70 78 79 73 61 63 61 74 33 4e 47 43 2f 73 6a 67 3d 3d } //1 VANe+lpxysacat3NGC/sjg==
		$a_01_3 = {57 6a 33 65 59 43 74 57 65 45 74 38 6a 71 48 55 68 43 6d 30 56 67 3d 3d } //1 Wj3eYCtWeEt8jqHUhCm0Vg==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}