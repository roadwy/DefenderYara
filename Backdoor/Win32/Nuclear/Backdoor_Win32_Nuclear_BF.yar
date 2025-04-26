
rule Backdoor_Win32_Nuclear_BF{
	meta:
		description = "Backdoor:Win32/Nuclear.BF,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {4e 75 63 6c 65 61 72 20 52 41 54 20 57 65 62 53 65 72 76 65 72 } //5 Nuclear RAT WebServer
		$a_01_1 = {5b 43 54 52 4c 5d } //1 [CTRL]
		$a_01_2 = {5b 54 41 42 5d } //1 [TAB]
		$a_01_3 = {7b 52 69 67 68 74 20 43 6c 69 63 6b 7d } //1 {Right Click}
		$a_01_4 = {7b 4d 69 64 64 6c 65 20 43 6c 69 63 6b 7d } //1 {Middle Click}
		$a_01_5 = {3f 61 63 74 69 6f 6e 3d 6c 6f 67 26 74 79 70 65 3d } //1 ?action=log&type=
		$a_01_6 = {26 75 73 65 72 3d } //1 &user=
		$a_01_7 = {7e 20 53 70 65 65 64 3a } //1 ~ Speed:
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}