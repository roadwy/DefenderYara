
rule Worm_Win32_Gamarue_PLA_{
	meta:
		description = "Worm:Win32/Gamarue.PLA!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 00 53 00 42 00 54 00 48 00 52 00 45 00 41 00 44 00 } //1 USBTHREAD
		$a_01_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 6d 00 73 00 69 00 66 00 66 00 30 00 78 00 31 00 } //1 Global\msiff0x1
		$a_03_2 = {25 03 00 00 80 79 05 48 83 c8 fc 40 83 c0 08 39 45 90 01 01 7d 4b e8 90 01 04 99 b9 4b 00 00 00 f7 f9 83 c2 30 89 55 90 01 01 83 7d 90 01 01 30 7c 06 83 7d 90 01 01 39 7e 0c 83 7d 90 01 01 61 7c 1b 83 7d 90 01 01 7a 7f 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}