
rule PWS_Win32_Lolyda_X{
	meta:
		description = "PWS:Win32/Lolyda.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d8 83 e3 05 83 fb 05 75 ?? 83 c0 03 89 45 f8 } //1
		$a_03_1 = {8b d8 83 e3 09 83 fb 09 75 ?? 83 c0 25 89 45 f0 8b 45 f0 } //1
		$a_01_2 = {83 fb 47 72 30 83 fb 49 76 22 83 fb 4a 76 26 83 fb 4d 76 15 83 fb 4e 76 1c 83 fb 51 76 08 83 fb 52 75 12 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}