
rule Backdoor_BAT_XWorm_SL_MTB{
	meta:
		description = "Backdoor:BAT/XWorm.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {78 77 6f 72 6d 36 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 xworm6.g.resources
		$a_81_1 = {24 63 35 38 66 36 66 66 32 2d 65 39 31 34 2d 34 33 36 66 2d 61 63 66 33 2d 34 37 63 64 39 61 31 30 39 62 34 33 } //1 $c58f6ff2-e914-436f-acf3-47cd9a109b43
		$a_81_2 = {78 77 6f 72 6d 36 2e 65 78 65 } //1 xworm6.exe
		$a_81_3 = {4c 45 49 43 41 20 47 65 6f 20 4f 66 66 69 63 65 } //1 LEICA Geo Office
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}