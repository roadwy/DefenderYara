
rule Trojan_Win32_Rustock_C{
	meta:
		description = "Trojan:Win32/Rustock.C,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 78 40 04 73 1a b8 90 01 02 41 00 e8 90 01 02 ff ff 6a 00 6a 06 e8 90 01 02 fe ff 6a ff e8 90 01 02 fe ff 90 00 } //01 00 
		$a_00_1 = {50 6f 72 74 69 6f 6e 73 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 39 2c 32 30 30 33 20 41 76 65 6e 67 65 72 20 62 79 20 4e 68 54 } //01 00  Portions Copyright (c) 1999,2003 Avenger by NhT
		$a_00_2 = {73 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //01 00  system\CurrentControlSet\Services\
		$a_01_3 = {32 30 38 2e 36 36 2e 31 39 34 2e 32 31 35 } //01 00  208.66.194.215
		$a_01_4 = {6f 6c 67 61 2d 72 65 6e 74 2d 61 2d 63 61 72 2e 69 6e 66 6f } //01 00  olga-rent-a-car.info
		$a_01_5 = {67 6d 61 69 6c 2e 63 6f 6d } //01 00  gmail.com
		$a_01_6 = {79 61 68 6f 6f 2e 63 6f 6d } //01 00  yahoo.com
		$a_00_7 = {73 69 77 73 79 6d 2e 73 79 73 } //01 00  siwsym.sys
		$a_00_8 = {73 79 73 65 72 2e 73 79 73 } //00 00  syser.sys
	condition:
		any of ($a_*)
 
}