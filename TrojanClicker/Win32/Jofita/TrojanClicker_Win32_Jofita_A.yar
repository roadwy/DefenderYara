
rule TrojanClicker_Win32_Jofita_A{
	meta:
		description = "TrojanClicker:Win32/Jofita.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 af eb 2b 66 3d 22 00 74 2f 66 3d 27 00 74 29 41 66 3d 3a 00 75 10 ff 05 } //1
		$a_01_1 = {3b f7 6a 02 5b 0f 84 e8 00 00 00 83 c6 0c eb 02 03 f3 0f b7 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}