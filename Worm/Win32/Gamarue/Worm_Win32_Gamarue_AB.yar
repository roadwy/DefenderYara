
rule Worm_Win32_Gamarue_AB{
	meta:
		description = "Worm:Win32/Gamarue.AB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b e5 5d c2 10 00 90 09 20 00 a1 ?? ?? ?? ?? 03 45 ?? 88 10 eb ?? 81 7d 14 ?? ?? ?? ?? 75 05 e8 ?? ?? ?? ?? ff 15 } //1
		$a_03_1 = {81 7d 14 88 88 88 08 75 05 e8 ?? ?? ?? ?? 8b e5 5d c2 10 00 } //1
		$a_03_2 = {8b e5 5d c2 10 00 90 09 13 00 8b 0d ?? ?? ?? ?? 03 4d ?? 88 01 eb ?? ff 15 90 1b 01 } //1
		$a_01_3 = {6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 ff 55 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*10) >=11
 
}