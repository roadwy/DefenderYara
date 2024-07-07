
rule PWS_Win32_Frethog_NF{
	meta:
		description = "PWS:Win32/Frethog.NF,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {65 58 70 6c 4f 72 45 52 2e 45 78 65 } //1 eXplOrER.Exe
		$a_01_1 = {5c 63 55 52 52 45 4e 54 63 4f 4e 54 52 4f 4c 73 45 54 5c 73 45 52 56 49 43 45 53 5c } //1 \cURRENTcONTROLsET\sERVICES\
		$a_00_2 = {25 73 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 25 73 } //1 %s:\Program Files\Common Files\%s
		$a_00_3 = {5c 53 65 74 55 70 2e 69 6e 66 00 00 25 63 25 73 25 63 00 00 5c 72 75 6e 2e 62 61 74 } //1
		$a_00_4 = {25 73 3f 6e 3d 25 73 26 70 3d 25 73 26 6c 3d 25 73 } //1 %s?n=%s&p=%s&l=%s
		$a_00_5 = {4a 4d 56 5f 56 4d 4a } //1 JMV_VMJ
		$a_00_6 = {54 53 53 61 66 65 45 64 69 74 2e 64 61 74 00 00 4c 6f 67 69 6e 43 74 72 6c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}