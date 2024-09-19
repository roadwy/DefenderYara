
rule Trojan_Win64_Razspy_YBQ_MTB{
	meta:
		description = "Trojan:Win64/Razspy.YBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 77 61 6c 6c 70 61 70 65 72 2e 70 6e 67 } //1 %swallpaper.png
		$a_01_1 = {68 74 74 70 3a 2f 2f 31 31 38 2e 32 34 33 2e 38 33 2e 37 30 2f } //1 http://118.243.83.70/
		$a_01_2 = {68 74 74 70 3a 2f 2f 37 33 2e 35 35 2e 31 32 38 2e 31 32 30 2f } //1 http://73.55.128.120/
		$a_01_3 = {51 7a 70 63 56 32 6c 75 5a 47 39 33 63 31 78 55 5a 57 31 77 58 46 4a 68 65 6e 4a 31 63 32 68 6c 62 6d 6c 35 5a 53 35 6c 65 47 55 3d } //1 QzpcV2luZG93c1xUZW1wXFJhenJ1c2hlbml5ZS5leGU=
		$a_01_4 = {2e 70 79 74 68 6f 6e 61 6e 79 77 68 65 72 65 2e 63 6f 6d } //1 .pythonanywhere.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}