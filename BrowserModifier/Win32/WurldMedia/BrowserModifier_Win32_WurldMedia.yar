
rule BrowserModifier_Win32_WurldMedia{
	meta:
		description = "BrowserModifier:Win32/WurldMedia,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 10 00 00 "
		
	strings :
		$a_01_0 = {74 6f 6f 6c 62 61 72 3d 6e 6f 2c 6c 6f 63 61 74 69 6f 6e 3d 6e 6f 2c 64 69 72 65 63 74 6f 72 69 65 73 3d 6e 6f 2c 6d 65 6e 75 62 61 72 3d 6e 6f 2c 73 63 72 6f 6c 6c 62 61 72 73 3d 6e 6f 2c 72 65 73 69 7a 61 62 6c 65 3d 6e 6f 2c 66 75 6c 6c 73 63 72 65 65 6e 3d 6e 6f } //3 toolbar=no,location=no,directories=no,menubar=no,scrollbars=no,resizable=no,fullscreen=no
		$a_01_1 = {77 65 72 75 6c 65 } //1 werule
		$a_01_2 = {55 70 64 61 74 65 57 68 65 6e } //2 UpdateWhen
		$a_01_3 = {68 74 74 70 3a 2f 2f 69 6e 73 2e 72 64 78 72 70 2e 63 6f 6d 2f 73 74 61 74 73 2f } //5 http://ins.rdxrp.com/stats/
		$a_01_4 = {3b 50 6c 61 74 66 6f 72 6d 3d } //1 ;Platform=
		$a_01_5 = {3b 4d 69 6e 6f 72 3d } //1 ;Minor=
		$a_01_6 = {3b 4d 61 6a 6f 72 3d } //1 ;Major=
		$a_01_7 = {3b 52 65 64 69 72 56 65 72 73 3d } //1 ;RedirVers=
		$a_01_8 = {6d 65 6e 75 62 61 64 } //2 menubad
		$a_01_9 = {6d 65 6e 75 67 6f 6f 64 } //2 menugood
		$a_01_10 = {6d 65 6e 75 64 65 66 61 75 6c 74 } //1 menudefault
		$a_01_11 = {6d 67 72 63 6f 64 65 } //1 mgrcode
		$a_01_12 = {2f 72 6d 69 74 6f 70 } //3 /rmitop
		$a_01_13 = {2f 72 6d 69 76 61 72 73 } //3 /rmivars
		$a_01_14 = {77 77 77 2e 72 64 78 72 70 2e 63 6f 6d } //3 www.rdxrp.com
		$a_01_15 = {77 77 77 2e 72 64 78 72 73 2e 63 6f 6d } //3 www.rdxrs.com
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*3+(#a_01_13  & 1)*3+(#a_01_14  & 1)*3+(#a_01_15  & 1)*3) >=25
 
}