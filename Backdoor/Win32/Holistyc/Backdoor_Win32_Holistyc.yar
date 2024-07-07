
rule Backdoor_Win32_Holistyc{
	meta:
		description = "Backdoor:Win32/Holistyc,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0b 00 00 "
		
	strings :
		$a_01_0 = {52 61 73 44 69 61 6c } //10 RasDial
		$a_01_1 = {48 6f 6c 69 73 74 79 63 44 6c 6c 2e 64 6c 6c } //3 HolistycDll.dll
		$a_01_2 = {74 68 65 70 61 79 6d 65 6e 74 63 65 6e 74 72 65 } //3 thepaymentcentre
		$a_01_3 = {25 73 5c 48 6f 6c 4d 6b 74 5c 25 64 2e 69 63 6f } //4 %s\HolMkt\%d.ico
		$a_01_4 = {45 6e 74 65 72 20 50 61 73 73 77 6f 72 64 } //3 Enter Password
		$a_01_5 = {48 6f 6c 69 73 74 79 63 43 61 6c 6c 53 74 61 74 73 2e 61 73 70 78 } //3 HolistycCallStats.aspx
		$a_01_6 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 65 6e 74 65 72 20 74 68 65 20 63 6f 6d 70 65 74 69 74 69 6f 6e 20 61 67 61 69 6e 3f } //1 Do you want to enter the competition again?
		$a_01_7 = {4d 61 78 50 61 79 6d 65 6e 74 } //1 MaxPayment
		$a_01_8 = {3f 68 6f 6c 69 73 74 79 63 4e 6f 64 69 61 6c 3d 79 26 } //3 ?holistycNodial=y&
		$a_01_9 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 48 6f 6c 69 73 74 79 63 2e 2e 2e } //3 Downloading Holistyc...
		$a_01_10 = {4a 61 6d 61 69 63 61 } //1 Jamaica
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*1) >=24
 
}