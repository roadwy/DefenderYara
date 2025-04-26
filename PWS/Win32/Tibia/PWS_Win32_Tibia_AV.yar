
rule PWS_Win32_Tibia_AV{
	meta:
		description = "PWS:Win32/Tibia.AV,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 00 74 00 65 00 70 00 3d 00 63 00 68 00 65 00 63 00 6b 00 65 00 6d 00 61 00 69 00 6c 00 26 00 6b 00 65 00 79 00 31 00 3d 00 } //2 step=checkemail&key1=
		$a_00_1 = {77 00 74 00 5f 00 67 00 75 00 61 00 72 00 64 00 } //1 wt_guard
		$a_01_2 = {63 68 61 72 61 63 74 65 72 5f 65 71 6c 69 73 74 } //1 character_eqlist
		$a_01_3 = {74 62 69 5f 72 65 61 64 65 64 5f 64 61 74 61 } //2 tbi_readed_data
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}