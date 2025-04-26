
rule Worm_Win32_Gamarue_PLD_{
	meta:
		description = "Worm:Win32/Gamarue.PLD!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 22 73 22 3a 25 6c 75 2c 22 74 22 3a 25 6c 75 2c 22 61 22 3a 22 25 73 22 2c 22 75 22 3a 22 } //1 {"s":%lu,"t":%lu,"a":"%s","u":"
		$a_01_1 = {2c 22 66 67 22 3a 22 } //1 ,"fg":"
		$a_00_2 = {83 c4 0c 83 e9 05 c6 00 e9 89 48 01 8d 45 14 50 6a 40 57 56 ff d3 85 c0 74 2b 8b 45 0c 2b c6 83 e8 05 89 46 01 8d 45 14 50 ff 75 14 c6 06 e9 57 56 ff d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}