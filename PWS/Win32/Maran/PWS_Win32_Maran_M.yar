
rule PWS_Win32_Maran_M{
	meta:
		description = "PWS:Win32/Maran.M,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 00 dd 6d 00 6a 00 6a 00 e8 ?? ?? ?? ?? a3 [0-08] 68 ?? ?? ?? ?? 68 10 27 00 00 6a 00 6a 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb 0c } //5
		$a_00_1 = {76 67 61 64 6f 77 6e 00 } //1 杶摡睯n
		$a_00_2 = {76 67 61 64 30 77 6e 00 } //1 杶摡眰n
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=6
 
}