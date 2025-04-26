
rule Trojan_Win32_Neoreblamy_GPPF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {6d 69 48 55 64 6e 67 50 4c 77 66 75 75 6f 53 7a 4f 73 56 58 6c 63 72 } //3 miHUdngPLwfuuoSzOsVXlcr
		$a_81_1 = {62 59 4c 42 49 71 69 6f 4b 6a 59 48 57 47 68 7a 49 4a } //2 bYLBIqioKjYHWGhzIJ
		$a_81_2 = {56 78 6b 56 6e 4b 62 46 4f 42 4c 66 62 4e 6e 4b } //1 VxkVnKbFOBLfbNnK
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}