
rule Worm_Win32_Gamarue_W{
	meta:
		description = "Worm:Win32/Gamarue.W,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 e7 c7 45 fc 90 01 01 00 00 00 0f b6 4d e7 83 f1 90 01 01 89 4d ec 90 00 } //2
		$a_01_1 = {8b 4d 08 8a 11 80 c2 01 8b 45 08 88 10 eb de } //2
		$a_01_2 = {64 65 73 6b 74 6f 70 2e 69 6e 69 00 6f 00 70 00 65 00 6e 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}