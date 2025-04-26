
rule PWS_Win32_Lolyda_W{
	meta:
		description = "PWS:Win32/Lolyda.W,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 6a 04 6a 05 ff 75 08 6a ff e8 ?? ?? ?? 00 6a 05 ff 75 0c ff 75 08 e8 ?? ?? ?? 00 83 c4 0c 6a 00 ff 75 fc 6a 05 ff 75 08 6a ff e8 ?? ?? ?? 00 b8 01 00 00 00 } //1
		$a_03_1 = {86 c4 c1 c0 10 86 c4 50 25 00 00 00 fc c1 c0 06 8a 80 ?? ?? ?? 10 aa 58 c1 e0 06 } //1
		$a_01_2 = {83 c4 0c 8b 45 10 03 45 e8 c6 00 e9 8b 45 0c 03 45 e8 8b 55 10 03 55 e8 2b c2 8b d0 83 ea 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}