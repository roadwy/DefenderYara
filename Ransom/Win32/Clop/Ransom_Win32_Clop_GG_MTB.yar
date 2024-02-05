
rule Ransom_Win32_Clop_GG_MTB{
	meta:
		description = "Ransom:Win32/Clop.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {25 73 5c 43 49 6f 70 52 65 61 64 4d 65 2e 74 78 74 } //%s\CIopReadMe.txt  01 00 
		$a_80_1 = {2f 63 20 64 65 6c 20 20 22 25 73 22 20 3e 3e 20 4e 55 4c } ///c del  "%s" >> NUL  01 00 
		$a_80_2 = {56 69 70 72 65 41 41 50 53 76 63 2e 65 78 65 } //VipreAAPSvc.exe  01 00 
		$a_02_3 = {f7 e6 8b c6 c1 ea 90 01 01 8b ca c1 e1 90 01 01 03 ca 03 c9 2b c1 8a 80 90 01 04 30 04 1e 46 3b f7 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}