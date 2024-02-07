
rule Trojan_Win32_Refeys_B{
	meta:
		description = "Trojan:Win32/Refeys.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 63 6f 6d 6d 61 6e 64 3d 6b 6e 6f 63 6b 26 75 73 65 72 6e 61 6d 65 3d } //01 00  &command=knock&username=
		$a_01_1 = {26 63 6f 6d 6d 61 6e 64 3d 64 65 61 63 74 69 76 61 74 65 26 6d 6f 64 75 6c 65 3d 68 76 6e 63 } //01 00  &command=deactivate&module=hvnc
		$a_41_2 = {04 3e 3c 3b 74 0d 84 c0 74 09 42 88 04 33 46 3b f1 72 ec 01 } //00 1b 
		$a_63_3 = {6d } //6d 61  m
		$a_64_4 = {75 70 64 61 74 65 5f 68 69 64 26 6e 65 77 5f 68 69 64 3d 00 00 02 00 80 10 00 00 a1 42 0f 29 a2 37 22 a0 16 00 11 4e 00 10 00 80 80 10 00 00 23 9f 29 58 97 03 10 5e 34 a8 96 75 00 10 00 80 80 10 00 00 06 18 6a c9 b3 f9 79 8f 2c d9 9a 9e 00 10 00 80 87 10 00 00 fb 1f 80 1b 67 15 b4 4e 96 99 05 0f a4 04 01 00 87 10 00 00 bb a7 0d } //49 41 
	condition:
		any of ($a_*)
 
}