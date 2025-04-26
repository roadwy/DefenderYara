
rule PWS_Win32_QQPass_GP{
	meta:
		description = "PWS:Win32/QQPass.GP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 4c 65 76 65 6c 3d 33 30 26 54 6f 4b 65 6e 3d 25 42 35 25 43 37 25 43 32 25 42 43 25 42 31 25 41 33 25 42 42 25 41 34 25 35 42 4e 4f 25 35 44 25 42 36 25 46 45 25 42 43 25 42 36 25 43 33 } //1 &Level=30&ToKen=%B5%C7%C2%BC%B1%A3%BB%A4%5BNO%5D%B6%FE%BC%B6%C3
		$a_01_1 = {69 33 2e 74 69 65 74 75 6b 75 2e 63 6f 6d 2f 38 30 31 64 62 38 37 36 63 64 63 61 61 39 36 63 2e 70 6e 67 } //1 i3.tietuku.com/801db876cdcaa96c.png
		$a_01_2 = {61 73 70 3f 41 63 74 69 6f 6e 3d 41 64 64 55 73 65 72 26 53 65 72 76 65 72 3d } //1 asp?Action=AddUser&Server=
		$a_01_3 = {71 71 2e 63 6f 6d 2f 6f 74 68 65 72 2f 63 69 6c 65 6e 74 2f 69 6e 64 65 78 32 2e 73 68 74 6d 6c } //1 qq.com/other/cilent/index2.shtml
		$a_01_4 = {67 65 74 69 6d 61 67 65 3f 61 69 64 3d 31 31 30 30 30 31 30 31 26 72 3d } //1 getimage?aid=11000101&r=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}