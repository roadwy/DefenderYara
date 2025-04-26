
rule Virus_Win32_Knat{
	meta:
		description = "Virus:Win32/Knat,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 46 08 28 31 9f 25 c7 46 58 00 00 00 00 0f b7 46 06 6b c0 28 8d bc 06 d0 00 00 00 6a 00 ff 75 dc e8 ?? ?? ?? 00 05 57 34 00 00 } //2
		$a_02_1 = {e8 00 00 00 00 83 2c 24 7a 5d 68 00 10 00 00 e8 ?? ?? 00 00 0b c0 0f 84 ?? ?? 00 00 97 68 00 08 00 00 57 56 e8 ?? ?? 00 00 66 83 3f 00 0f 84 ?? ?? 00 00 50 57 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_02_1  & 1)*1) >=1
 
}