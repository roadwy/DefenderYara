
rule HackTool_Win64_Logoloz_DZ_MTB{
	meta:
		description = "HackTool:Win64/Logoloz.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6e 69 63 6f 63 68 61 33 30 2f 6c 69 67 6f 6c 6f 2d 6e 67 } //2 github.com/nicocha30/ligolo-ng
		$a_01_2 = {44 7a 44 49 46 36 53 64 37 47 44 32 73 58 30 6b 44 46 70 48 41 73 4a 4d 59 34 4c 2b 4f 66 54 76 74 75 61 51 73 4f 59 58 78 7a 6b } //2 DzDIF6Sd7GD2sX0kDFpHAsJMY4L+OfTvtuaQsOYXxzk
		$a_01_3 = {63 6c 69 65 6e 74 20 66 69 6e 69 73 68 65 64 } //1 client finished
		$a_01_4 = {63 51 72 69 79 69 55 76 6a 54 77 4f 48 67 38 51 5a 61 50 69 68 4c 57 65 52 41 41 56 6f 43 70 45 30 30 49 55 50 6e 30 42 6a 74 38 } //2 cQriyiUvjTwOHg8QZaPihLWeRAAVoCpE00IUPn0Bjt8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=8
 
}