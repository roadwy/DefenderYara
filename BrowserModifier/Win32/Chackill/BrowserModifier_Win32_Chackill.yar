
rule BrowserModifier_Win32_Chackill{
	meta:
		description = "BrowserModifier:Win32/Chackill,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c } //1 Software\Microsoft\Windows\CurrentVersion\explorer\Browser Helper Objects\
		$a_01_1 = {61 4b 69 6c 6c 65 72 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1
		$a_01_2 = {44 44 44 37 46 45 45 36 2d 41 39 35 33 2d 30 38 37 31 2d 35 44 45 43 2d 42 43 46 39 38 31 41 44 37 36 33 33 } //1 DDD7FEE6-A953-0871-5DEC-BCF981AD7633
		$a_01_3 = {2f 2f 76 67 2e 6c 61 2f 61 64 64 75 72 6c 2e 68 74 6d } //1 //vg.la/addurl.htm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}