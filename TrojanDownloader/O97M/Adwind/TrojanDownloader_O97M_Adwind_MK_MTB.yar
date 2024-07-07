
rule TrojanDownloader_O97M_Adwind_MK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Adwind.MK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 25 5e 74 25 5e 74 25 5e 70 25 5e 3a 25 5e 2f 25 5e 2f 25 5e 6c 25 5e 69 25 5e 6d 25 5e 69 25 5e 74 25 5e 65 25 5e 64 25 5e 65 25 5e 64 25 5e 69 25 5e 74 25 5e 69 25 5e 6f 25 5e 6e 25 5e 70 25 5e 68 25 5e 6f 25 5e 74 25 5e 6f 25 5e 73 25 5e 2e 25 5e 6e 25 5e 6c } //h%^t%^t%^p%^:%^/%^/%^l%^i%^m%^i%^t%^e%^d%^e%^d%^i%^t%^i%^o%^n%^p%^h%^o%^t%^o%^s%^.%^n%^l  1
		$a_80_1 = {74 74 20 3d 20 52 65 70 6c 61 63 65 28 74 74 2c 20 22 25 5e 22 2c 20 22 22 29 } //tt = Replace(tt, "%^", "")  1
		$a_80_2 = {63 63 20 3d 20 53 74 72 69 6e 67 } //cc = String  1
		$a_80_3 = {53 68 65 6c 6c 4f 62 6a 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 63 63 2c 20 74 74 } //ShellObj.ShellExecute cc, tt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}