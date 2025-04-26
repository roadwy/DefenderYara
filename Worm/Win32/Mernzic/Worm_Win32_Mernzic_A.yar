
rule Worm_Win32_Mernzic_A{
	meta:
		description = "Worm:Win32/Mernzic.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 65 6a 2e 6a 64 6a 6d 6a 63 } //1 jej.jdjmjc
		$a_01_1 = {65 78 69 74 72 65 6d 6f 74 65 65 76 65 6e 74 } //1 exitremoteevent
		$a_01_2 = {5c 5c 2e 5c 70 69 70 65 5c 6c 6f 63 61 6c 63 61 74 69 6f 6e } //1 \\.\pipe\localcation
		$a_01_3 = {63 7a 6d 69 6e 69 6e 65 72 72 00 00 63 7a 6d 69 6e 69 6e 69 6e 00 00 00 5c 5c 2e 5c 70 69 70 65 5c 25 73 25 73 25 64 00 63 7a 6d 69 6e 69 6e 6f 75 74 } //2
		$a_01_4 = {44 6f 6e 27 74 20 75 73 65 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 21 2c 43 6f 6d 70 75 74 65 72 4e 61 6d 65 28 29 20 47 65 74 20 66 61 69 6c 65 64 20 3a 29 } //1 Don't use this computer!,ComputerName() Get failed :)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=4
 
}