
rule Trojan_Win32_IISBackdoor_G{
	meta:
		description = "Trojan:Win32/IISBackdoor.G,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {62 76 2b 79 41 6e 3d 76 74 69 50 2a 61 76 76 } //bv+yAn=vtiP*avv  2
		$a_80_1 = {5c 49 49 53 5f 62 61 63 6b 64 6f 6f 72 2d 6d 61 73 74 65 72 5c 49 49 53 5f 62 61 63 6b 64 6f 6f 72 5f 64 6c 6c 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 43 6f 6e 6e 53 65 72 76 69 63 65 2e 70 64 62 } //\IIS_backdoor-master\IIS_backdoor_dll\obj\Release\ConnService.pdb  2
		$a_80_2 = {58 6f 72 43 6f 6e 76 65 72 74 42 61 63 6b } //XorConvertBack  2
		$a_80_3 = {78 6f 72 4b 65 79 42 79 74 65 73 } //xorKeyBytes  2
		$a_80_4 = {49 48 74 74 70 4d 6f 64 75 6c 65 } //IHttpModule  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=10
 
}