
rule PWS_Win32_Magovel_A{
	meta:
		description = "PWS:Win32/Magovel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 3a ff 33 55 f8 e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 df } //1
		$a_01_1 = {66 83 f8 03 74 06 66 83 f8 04 75 53 6a 32 } //1
		$a_02_2 = {26 76 65 72 3d 90 09 04 00 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}