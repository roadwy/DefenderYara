
rule PWS_Win32_Tibia_AH{
	meta:
		description = "PWS:Win32/Tibia.AH,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 74 69 62 69 61 2d 69 6e 6a 65 63 74 2e 63 6f 6d 2f 90 02 08 2e 70 68 70 90 00 } //0a 00 
		$a_00_1 = {6c 6f 67 69 6e 30 31 2e 74 69 62 69 61 2e 63 6f 6d } //0a 00  login01.tibia.com
		$a_00_2 = {2f 63 20 61 74 74 72 69 62 20 2b 73 20 2b 68 } //01 00  /c attrib +s +h
		$a_00_3 = {69 6e 66 6e 61 6d 65 3d } //01 00  infname=
		$a_00_4 = {26 69 6e 66 69 64 3d } //01 00  &infid=
		$a_00_5 = {26 70 61 73 73 3d } //01 00  &pass=
		$a_00_6 = {26 61 63 63 3d } //01 00  &acc=
		$a_00_7 = {26 6e 69 63 6b 3d } //00 00  &nick=
	condition:
		any of ($a_*)
 
}