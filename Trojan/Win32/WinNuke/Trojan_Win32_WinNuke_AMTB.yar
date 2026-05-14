
rule Trojan_Win32_WinNuke_AMTB{
	meta:
		description = "Trojan:Win32/WinNuke!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {57 69 6e 4e 75 6b 65 20 39 38 20 41 74 74 61 63 6b 69 6e 67 } //WinNuke 98 Attacking  1
		$a_80_1 = {57 69 6e 4e 75 6b 65 21 20 57 69 6e 27 39 38 20 2f 20 44 6f 6e 27 74 20 54 6f 75 63 68 20 69 74 73 20 21 } //WinNuke! Win'98 / Don't Touch its !  1
		$a_80_2 = {4e 75 6b 65 20 41 74 74 61 63 6b } //Nuke Attack  1
		$a_80_3 = {57 69 6e 4e 75 6b 65 20 39 38 20 41 74 74 61 63 6b 69 6e 67 2e 76 62 70 } //WinNuke 98 Attacking.vbp  1
		$a_80_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 63 6b 65 72 77 6f 72 6c 64 2e 63 6f 6d 2f 6e 75 6b 65 2e 68 74 6d 6c } //http://www.hackerworld.com/nuke.html  1
		$a_80_5 = {57 69 6e 4e 75 6b 65 20 41 74 74 61 63 6b 69 6e 67 20 50 6f 72 74 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //WinNuke Attacking Port Successfully  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}