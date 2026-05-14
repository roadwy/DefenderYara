
rule _#PUA_Block_FileZilla_BundleInstaller{
	meta:
		description = "!#PUA:Block:FileZilla_BundleInstaller,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 69 6c 65 5a 69 6c 6c 61 5f 33 2e 36 33 2e 32 5f 77 69 6e 33 32 2d 73 65 74 75 70 2e 65 78 65 } //FileZilla_3.63.2_win32-setup.exe  1
		$a_80_1 = {66 69 6c 65 7a 69 6c 6c 61 2d 70 72 6f 6a 65 63 74 2e 6f 72 67 2f 64 6f 77 6e 6c 6f 61 64 } //filezilla-project.org/download  1
		$a_80_2 = {54 69 6d 20 4b 6f 73 73 65 } //Tim Kosse  1
		$a_80_3 = {46 69 6c 65 5a 69 6c 6c 61 20 46 54 50 20 43 6c 69 65 6e 74 } //FileZilla FTP Client  1
		$a_80_4 = {6f 66 66 65 72 2d 65 6e 61 62 6c 65 64 20 69 6e 73 74 61 6c 6c 65 72 } //offer-enabled installer  1
		$a_80_5 = {50 6c 61 79 61 4e 65 78 74 20 4c 4c 43 } //PlayaNext LLC  1
		$a_80_6 = {70 6c 61 79 61 6e 65 78 74 2e 63 6f 6d } //playanext.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=6
 
}
rule _#PUA_Block_FileZilla_BundleInstaller_2{
	meta:
		description = "!#PUA:Block:FileZilla_BundleInstaller,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6f 00 66 00 66 00 65 00 72 00 73 00 2e 00 66 00 69 00 6c 00 65 00 7a 00 69 00 6c 00 6c 00 61 00 2d 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 6f 00 72 00 67 00 2f 00 6f 00 66 00 66 00 65 00 72 00 2e 00 70 00 68 00 70 00 3f 00 76 00 3d 00 } //1 https://offers.filezilla-project.org/offer.php?v=
		$a_01_1 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 63 00 6f 00 6e 00 73 00 69 00 64 00 65 00 72 00 20 00 74 00 68 00 69 00 73 00 20 00 6f 00 70 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 20 00 6f 00 66 00 66 00 65 00 72 00 } //1 Please consider this optional offer
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Software\FileZilla Client
		$a_01_3 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 54 00 69 00 6d 00 20 00 4b 00 6f 00 73 00 73 00 65 00 } //1
		$a_01_4 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 46 00 69 00 6c 00 65 00 5a 00 69 00 6c 00 6c 00 61 00 20 00 46 00 54 00 50 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}