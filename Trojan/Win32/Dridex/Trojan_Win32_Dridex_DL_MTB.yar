
rule Trojan_Win32_Dridex_DL_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {47 72 72 70 70 64 65 6d 6d 72 46 70 70 65 } //GrrppdemmrFppe  03 00 
		$a_80_1 = {47 72 70 70 70 6d 64 65 2e 70 64 62 } //Grpppmde.pdb  03 00 
		$a_80_2 = {53 65 6c 66 20 65 78 } //Self ex  03 00 
		$a_80_3 = {4d 70 72 49 6e 66 6f 42 6c 6f 63 6b 52 65 6d 6f 76 65 } //MprInfoBlockRemove  03 00 
		$a_80_4 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //InternetCrackUrlA  03 00 
		$a_80_5 = {57 72 69 74 65 50 72 69 76 61 74 65 50 72 6f 66 69 6c 65 53 74 72 75 63 74 57 } //WritePrivateProfileStructW  03 00 
		$a_80_6 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //GetTempFileNameA  00 00 
	condition:
		any of ($a_*)
 
}