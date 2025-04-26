
rule Worm_Win32_SillyShareCopy_AQ{
	meta:
		description = "Worm:Win32/SillyShareCopy.AQ,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 } //1 shellexecute=
		$a_01_1 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //1 [autorun]
		$a_01_2 = {6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 } //1 open\command=
		$a_01_3 = {6d 63 69 73 65 6e 64 73 74 72 69 6e 67 61 } //1 mcisendstringa
		$a_01_4 = {4b 00 68 00 6f 00 61 00 } //1 Khoa
		$a_01_5 = {73 70 65 72 73 6b } //1 spersk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}