
rule Trojan_Win32_Guloader_ASB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {67 75 69 64 73 69 72 65 5c 41 6e 6c 67 73 67 61 72 74 6e 65 72 69 65 74 2e 6c 6e 6b } //2 guidsire\Anlgsgartneriet.lnk
		$a_01_1 = {58 61 6e 74 68 6f 70 73 69 6e 38 5c 64 69 61 6d 62 2e 6c 69 74 } //2 Xanthopsin8\diamb.lit
		$a_01_2 = {4a 75 6e 67 6d 61 6e 64 65 6e 73 31 35 5c 66 69 73 6b 65 66 61 72 74 6a 65 72 } //1 Jungmandens15\fiskefartjer
		$a_01_3 = {70 68 79 74 6f 73 6f 63 69 6f 6c 6f 67 69 63 61 6c 6c 79 2e 74 78 74 } //1 phytosociologically.txt
		$a_01_4 = {46 72 65 64 73 76 61 6c 67 65 74 32 31 34 5c 6e 61 74 69 6f 6e 61 6c 69 6e 64 6b 6f 6d 73 74 65 6e } //1 Fredsvalget214\nationalindkomsten
		$a_01_5 = {68 61 6d 70 74 6f 6e 2e 61 6e 74 } //1 hampton.ant
		$a_01_6 = {6b 6f 6e 6f 6d 69 73 65 72 65 74 5c 55 6e 69 6e 73 74 61 6c 6c 5c 67 65 72 6f 6e 74 6f 6c 6f 67 69 63 } //1 konomiseret\Uninstall\gerontologic
		$a_01_7 = {62 6a 65 72 67 6b 72 79 73 74 61 6c 6c 65 6e 2e 73 61 6d } //1 bjergkrystallen.sam
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}