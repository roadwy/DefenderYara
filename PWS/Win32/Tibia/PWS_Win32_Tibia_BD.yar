
rule PWS_Win32_Tibia_BD{
	meta:
		description = "PWS:Win32/Tibia.BD,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 6e 66 65 63 74 6f 72 5f 69 64 } //6 infector_id
		$a_01_1 = {74 74 62 69 5f 64 61 74 61 } //3 ttbi_data
		$a_01_2 = {73 6b 69 6c 6c 5f 70 6f 69 6e 74 73 5f 66 69 73 68 69 6e 67 } //2 skill_points_fishing
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=11
 
}