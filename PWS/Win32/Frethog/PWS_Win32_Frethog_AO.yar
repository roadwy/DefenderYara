
rule PWS_Win32_Frethog_AO{
	meta:
		description = "PWS:Win32/Frethog.AO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 2a 66 8b 45 ec 66 3b 45 dc 75 19 66 8b 45 ee 66 3b 45 de 75 0f 0f b7 45 e2 0f b7 4d f2 2b c8 83 f9 ?? 7c 07 } //1
		$a_01_1 = {6a 04 50 68 2b e0 22 00 ff 75 08 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}