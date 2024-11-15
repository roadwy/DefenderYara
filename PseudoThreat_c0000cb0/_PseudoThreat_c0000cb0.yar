
rule _PseudoThreat_c0000cb0{
	meta:
		description = "!PseudoThreat_c0000cb0,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d } //1 Host: download.%s.com
		$a_00_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 78 70 75 70 64 61 74 65 2e 65 78 65 } //1 C:\Windows\xpupdate.exe
		$a_01_2 = {57 69 6e 64 6f 77 73 20 75 70 64 61 74 65 20 6c 6f 61 64 65 72 } //1 Windows update loader
		$a_00_3 = {43 3a 5c 49 6e 73 74 61 6c 6c } //1 C:\Install
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 44 65 73 6b 74 6f 70 5c 47 65 6e 65 72 61 6c } //1 SOFTWARE\Microsoft\Internet Explorer\Desktop\General
		$a_02_5 = {47 45 54 20 2f [0-08] 2e 70 68 70 3f 26 61 64 76 69 64 3d } //1
		$a_02_6 = {47 45 54 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f [0-08] 2e 70 68 70 3f 26 61 64 76 69 64 3d } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1) >=6
 
}