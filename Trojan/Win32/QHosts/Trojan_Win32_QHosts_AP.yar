
rule Trojan_Win32_QHosts_AP{
	meta:
		description = "Trojan:Win32/QHosts.AP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0c 00 00 "
		
	strings :
		$a_03_0 = {25 30 34 5c [0-10] 2e 74 78 74 00 } //1
		$a_03_1 = {25 30 34 5c [0-10] 2e 65 78 65 00 } //1
		$a_03_2 = {25 30 34 5c [0-10] 2e 6a 70 67 00 } //1
		$a_01_3 = {25 30 32 5c 53 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c } //1 %02\System32\drivers\etc\
		$a_03_4 = {65 63 68 6f 20 25 [0-10] 25 20 3e 3e 20 20 68 6f 73 74 73 0d 0a } //1
		$a_03_5 = {65 63 68 6f 20 20 25 [0-10] 25 20 20 20 3e 3e 20 20 68 6f 73 74 73 0d 0a } //1
		$a_01_6 = {0d 0a 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 0d 0a } //1
		$a_01_7 = {3d 25 73 79 73 74 65 6d 72 6f 6f 74 25 25 } //1 =%systemroot%%
		$a_01_8 = {3d 6f 6e 74 61 6b 74 65 2e 0d 0a } //1
		$a_03_9 = {3d 2e 0d 0a 73 65 74 20 [0-10] 3d 72 0d 0a 73 65 74 20 [0-10] 3d 75 0d 0a } //2
		$a_01_10 = {3a 2f 2f 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2e 72 75 00 } //1
		$a_01_11 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6f 6c 6f 6c 6f 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*2+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=6
 
}