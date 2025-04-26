
rule Ransom_Win32_Urausy_I{
	meta:
		description = "Ransom:Win32/Urausy.I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4d c4 89 4a 01 c6 42 05 83 c6 42 06 2c c6 42 07 24 c6 42 08 05 } //1
		$a_03_1 = {89 f7 83 c9 ff 31 c0 f2 ae c7 47 fb 2e (69 6e 66|74 67 61) 56 ff 93 } //1
		$a_01_2 = {5b b0 2e aa b8 68 74 6d 6c ab 31 c0 aa } //1
		$a_01_3 = {25 00 78 00 25 00 78 00 2e 00 78 00 6d 00 6c 00 } //1 %x%x.xml
		$a_01_4 = {26 6c 74 3b 00 26 67 74 3b 00 26 61 6d 70 3b 00 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //1 氦㭴☀瑧;愦灭;敇䵴摯汵䙥汩乥浡䅥
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Ransom_Win32_Urausy_I_2{
	meta:
		description = "Ransom:Win32/Urausy.I,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4d c4 89 4a 01 c6 42 05 83 c6 42 06 2c c6 42 07 24 c6 42 08 05 } //1
		$a_01_1 = {89 f7 83 c9 ff 31 c0 f2 ae c7 47 fb 2e 69 6e 66 56 ff 93 } //1
		$a_01_2 = {5b b0 2e aa b8 68 74 6d 6c ab 31 c0 aa } //1
		$a_01_3 = {25 00 78 00 25 00 78 00 2e 00 78 00 6d 00 6c 00 } //1 %x%x.xml
		$a_01_4 = {26 6c 74 3b 00 26 67 74 3b 00 26 61 6d 70 3b 00 47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //1 氦㭴☀瑧;愦灭;敇䵴摯汵䙥汩乥浡䅥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}