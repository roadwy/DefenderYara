
rule Trojan_Win32_SpyNoon_SSM_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.SSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {6c 6d 6f 6c 6b 69 76 6a 77 63 76 6d 79 71 63 70 69 68 68 69 } //lmolkivjwcvmyqcpihhi  01 00 
		$a_80_1 = {66 78 68 6e 2e 64 6c 6c } //fxhn.dll  01 00 
		$a_80_2 = {66 74 74 64 6a 69 78 6e 6d 68 6f } //fttdjixnmho  01 00 
		$a_80_3 = {6e 62 6b 6d 6d 70 6d 71 6f 78 63 } //nbkmmpmqoxc  01 00 
		$a_80_4 = {62 6a 6f 6b 6b 6a 6f 65 74 68 } //bjokkjoeth  01 00 
		$a_80_5 = {75 72 68 6d 78 62 61 6d 65 6e 64 76 6e } //urhmxbamendvn  01 00 
		$a_80_6 = {25 41 50 50 44 41 54 41 25 } //%APPDATA%  01 00 
		$a_80_7 = {6d 61 6a 69 64 6c 65 63 79 72 } //majidlecyr  01 00 
		$a_80_8 = {6d 6b 71 71 6e 7a 6b 67 6c 70 65 69 6c 66 } //mkqqnzkglpeilf  01 00 
		$a_80_9 = {25 54 45 4d 50 25 } //%TEMP%  01 00 
		$a_80_10 = {65 6c 64 6a 6e 79 6c 62 77 63 73 64 } //eldjnylbwcsd  00 00 
	condition:
		any of ($a_*)
 
}