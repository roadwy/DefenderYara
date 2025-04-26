
rule Worm_Win32_Rebhip_X{
	meta:
		description = "Worm:Win32/Rebhip.X,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 5f 58 5f 42 4c 4f 43 4b 4d 4f 55 53 45 } //1 x_X_BLOCKMOUSE
		$a_01_1 = {5f 78 5f 58 5f 50 41 53 53 57 4f 52 44 } //1 _x_X_PASSWORD
		$a_01_2 = {23 23 23 23 40 23 23 23 23 20 23 23 23 } //1 ####@#### ###
		$a_01_3 = {55 6e 69 74 43 6f 6d 61 6e 64 6f 73 } //1 UnitComandos
		$a_01_4 = {43 47 2d 43 47 2d 43 47 2d 43 47 } //1 CG-CG-CG-CG
		$a_01_5 = {58 58 2d 58 58 2d 58 58 2d 58 58 } //1 XX-XX-XX-XX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}