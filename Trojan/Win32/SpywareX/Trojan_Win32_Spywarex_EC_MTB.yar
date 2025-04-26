
rule Trojan_Win32_Spywarex_EC_MTB{
	meta:
		description = "Trojan:Win32/Spywarex.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 6f 6d 65 6c 6f 63 6b 2f 73 70 79 73 74 61 74 75 73 } //1 homelock/spystatus
		$a_81_1 = {54 49 41 4e 20 57 41 4e 47 20 47 41 49 20 44 49 20 48 55 } //1 TIAN WANG GAI DI HU
		$a_81_2 = {68 6f 6d 65 6c 6f 63 6b 2f 6c 6f 63 6b } //1 homelock/lock
		$a_81_3 = {62 72 6f 77 73 65 72 2d 68 6f 6d 65 2d 6c 6f 63 6b 65 72 } //1 browser-home-locker
		$a_81_4 = {62 68 6f 6c 6f 61 64 65 72 2e 77 69 6e 33 32 2e 72 65 6c 65 61 73 65 2e 70 64 62 } //1 bholoader.win32.release.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}