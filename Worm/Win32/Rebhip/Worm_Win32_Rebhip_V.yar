
rule Worm_Win32_Rebhip_V{
	meta:
		description = "Worm:Win32/Rebhip.V,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 47 00 2d 00 43 00 47 00 2d 00 43 00 47 00 2d 00 43 00 47 00 } //1 CG-CG-CG-CG
		$a_01_1 = {58 00 58 00 2d 00 58 00 58 00 2d 00 58 00 58 00 2d 00 58 00 58 00 } //1 XX-XX-XX-XX
		$a_01_2 = {08 00 43 00 45 00 52 00 42 00 45 00 52 00 55 00 53 00 } //1
		$a_01_3 = {06 00 53 00 50 00 59 00 4e 00 45 00 54 00 } //1
		$a_01_4 = {8a 54 1a ff 80 f2 bc 88 54 18 ff 43 4e 75 e6 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5) >=6
 
}