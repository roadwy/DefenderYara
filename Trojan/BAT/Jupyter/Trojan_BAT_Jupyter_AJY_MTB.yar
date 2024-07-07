
rule Trojan_BAT_Jupyter_AJY_MTB{
	meta:
		description = "Trojan:BAT/Jupyter.AJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 1b 59 8d 90 01 03 01 0b 16 0d 2b 0c 07 09 06 09 1b 58 91 9c 09 17 58 0d 09 07 8e 69 32 ee 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Jupyter_AJY_MTB_2{
	meta:
		description = "Trojan:BAT/Jupyter.AJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {16 0c 2b 4c 07 08 07 08 91 07 08 17 58 91 61 d2 9c 07 8e 69 17 59 8d 21 00 00 01 0d 16 13 04 16 13 05 2b 1f 08 11 04 33 06 11 04 17 58 13 04 09 11 05 07 11 04 91 9c 11 04 17 58 13 04 11 05 17 58 } //2
		$a_01_1 = {73 00 70 00 61 00 63 00 65 00 74 00 72 00 75 00 63 00 6b 00 2e 00 62 00 69 00 7a 00 } //1 spacetruck.biz
		$a_01_2 = {43 00 53 00 2d 00 44 00 4e 00 2f 00 31 00 2e 00 33 00 } //1 CS-DN/1.3
		$a_01_3 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 } //1 \AppData\Local\Google\Chrome\User Data
		$a_01_4 = {6a 00 75 00 70 00 79 00 74 00 65 00 72 00 } //1 jupyter
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}