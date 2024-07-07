
rule Worm_Win32_Rimecud_HM{
	meta:
		description = "Worm:Win32/Rimecud.HM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6f 6d 2f 73 65 74 75 70 5f 62 2e 61 73 70 3f 70 72 6a 3d 90 02 03 26 70 69 64 3d 90 02 03 26 6d 61 63 3d 90 00 } //1
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 02 05 2e 77 69 6e 73 6f 66 74 31 2e 63 6f 6d 2f 90 00 } //1
		$a_00_2 = {2f 72 65 63 65 69 76 65 2f 72 5f 61 75 74 6f 69 64 63 6e 74 2e 61 73 70 3f 6d 65 72 5f 73 65 71 3d 25 73 26 72 65 61 6c 69 64 3d 25 73 } //1 /receive/r_autoidcnt.asp?mer_seq=%s&realid=%s
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}