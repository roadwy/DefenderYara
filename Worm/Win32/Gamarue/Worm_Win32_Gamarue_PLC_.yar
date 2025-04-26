
rule Worm_Win32_Gamarue_PLC_{
	meta:
		description = "Worm:Win32/Gamarue.PLC!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2c 22 73 35 22 3a 25 6c 75 } //1 ,"s5":%lu
		$a_03_1 = {ff 75 08 e8 ?? ?? ?? ?? 0b c0 74 05 83 f8 ff 75 02 eb 4b 80 bd d4 fe ff ff 05 75 42 0f b6 8d d5 fe ff ff 85 c9 74 37 8d bd d6 fe ff ff 33 c0 f2 ae 75 2b c6 85 cf fe ff ff 00 c7 85 d0 fe ff ff 05 00 00 00 6a 00 6a 02 8d 85 d0 fe ff ff 50 ff 75 08 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}