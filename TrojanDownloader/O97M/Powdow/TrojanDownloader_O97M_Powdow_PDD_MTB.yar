
rule TrojanDownloader_O97M_Powdow_PDD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PDD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 22 63 6e 65 2d 31 6e 69 77 2d 65 22 73 3d 73 2b 22 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 5c 30 2e 31 22 73 3d 73 2b 22 76 5c 6c 6c 65 68 73 72 65 77 6f 70 73 22 73 3d 73 2b 22 77 6f 64 6e 69 77 5c 32 33 6d 65 22 73 3d 73 2b 22 74 73 79 73 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 78 3d 73 74 72 72 65 76 65 72 73 65 28 73 29 } //01 00  ="cne-1niw-e"s=s+"xe.llehsrewop\0.1"s=s+"v\llehsrewops"s=s+"wodniw\23me"s=s+"tsys\swodniw\:c"x=strreverse(s)
		$a_01_1 = {78 3d 78 2b 22 73 74 22 78 3d 78 2b 22 61 72 74 22 78 3d 78 2b 22 2f 6d 22 78 3d 78 2b 22 69 22 2b 22 6e 22 70 72 65 66 69 78 31 3d 78 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00  x=x+"st"x=x+"art"x=x+"/m"x=x+"i"+"n"prefix1=xendfunction
		$a_01_2 = {3d 73 68 65 6c 6c 28 62 61 74 2c 30 29 65 6e 64 73 75 62 70 72 69 76 61 74 65 73 75 62 } //00 00  =shell(bat,0)endsubprivatesub
	condition:
		any of ($a_*)
 
}