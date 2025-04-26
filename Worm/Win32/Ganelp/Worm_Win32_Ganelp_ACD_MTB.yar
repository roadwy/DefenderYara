
rule Worm_Win32_Ganelp_ACD_MTB{
	meta:
		description = "Worm:Win32/Ganelp.ACD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {54 65 55 50 69 69 6e 68 62 6d 6f 61 } //TeUPiinhbmoa  3
		$a_80_1 = {48 48 4a 4a 4f 43 4e 4e 47 45 41 4d } //HHJJOCNNGEAM  3
		$a_80_2 = {6d 6f 55 70 75 43 73 59 } //moUpuCsY  3
		$a_80_3 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 41 64 64 52 65 66 } //EVENT_SINK_AddRef  3
		$a_80_4 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 52 65 6c 65 61 73 65 } //EVENT_SINK_Release  3
		$a_80_5 = {45 56 45 4e 54 5f 53 49 4e 4b 5f 51 75 65 72 79 49 6e 74 65 72 66 61 63 65 } //EVENT_SINK_QueryInterface  3
		$a_80_6 = {2b 64 2b 6b 30 55 2e 64 6c 6c 2e 64 6c 6c } //+d+k0U.dll.dll  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}