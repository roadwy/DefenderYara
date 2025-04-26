
rule Worm_Win32_Autorun_TO{
	meta:
		description = "Worm:Win32/Autorun.TO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 63 00 68 00 69 00 74 00 5c 00 4d 00 4f 00 52 00 47 00 41 00 4e 00 55 00 53 00 42 00 49 00 4e 00 46 00 45 00 43 00 54 00 4f 00 52 00 5c 00 54 00 50 00 57 00 72 00 6d 00 32 00 2e 00 76 00 62 00 70 00 } //1 :\chit\MORGANUSBINFECTOR\TPWrm2.vbp
		$a_01_1 = {41 00 3a 00 5c 00 6c 00 69 00 65 00 6b 00 65 00 2e 00 65 00 78 00 } //1 A:\lieke.ex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}