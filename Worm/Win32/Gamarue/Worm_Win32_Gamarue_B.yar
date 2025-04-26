
rule Worm_Win32_Gamarue_B{
	meta:
		description = "Worm:Win32/Gamarue.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 65 78 65 00 68 6f 73 74 2e 68 73 76 63 68 8b ?? 33 ?? ?? ?? 6a 03 ?? 6a 01 68 00 00 00 80 ?? ff 55 f8 } //1
		$a_03_1 = {b0 68 aa 8b 45 ?? ab b0 c3 aa 8b 5d ?? 03 5b 3c } //1
		$a_00_2 = {69 64 3a 25 6c 75 7c 74 69 64 3a 25 6c 75 } //1 id:%lu|tid:%lu
		$a_01_3 = {64 8b 1d 30 00 00 00 8b 5b 0c 8b 5b 0c 83 c3 24 8b 5b 04 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 53 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}