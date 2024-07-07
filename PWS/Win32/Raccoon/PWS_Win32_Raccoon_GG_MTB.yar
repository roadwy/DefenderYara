
rule PWS_Win32_Raccoon_GG_MTB{
	meta:
		description = "PWS:Win32/Raccoon.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0b 00 00 "
		
	strings :
		$a_80_0 = {2f 73 74 61 74 73 2f 70 6f 73 74 62 61 63 6b 2e 70 68 70 3f 74 72 61 63 6b 69 64 3d } ///stats/postback.php?trackid=  1
		$a_80_1 = {2f 73 74 61 74 73 2f 67 65 74 73 74 61 74 2e 70 68 70 3f 70 75 62 3d } ///stats/getstat.php?pub=  1
		$a_80_2 = {2f 64 6c 63 2f 70 61 72 74 6e 65 72 2e 70 68 70 3f 70 75 62 3d } ///dlc/partner.php?pub=  1
		$a_80_3 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } ///download.php  1
		$a_80_4 = {26 70 6f 73 74 62 61 63 6b 3d } //&postback=  1
		$a_80_5 = {26 75 73 65 72 3d } //&user=  1
		$a_80_6 = {2f 64 6f 2e 70 68 70 3f 70 75 62 3d } ///do.php?pub=  1
		$a_80_7 = {2f 73 74 61 74 73 2f 69 74 73 72 75 2e 70 68 70 3f 70 75 62 3d } ///stats/itsru.php?pub=  1
		$a_80_8 = {4b 49 4c 4c 4d 45 } //KILLME  1
		$a_80_9 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } ///c taskkill /im  1
		$a_80_10 = {2f 66 20 26 20 65 72 61 73 65 } ///f & erase  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=9
 
}