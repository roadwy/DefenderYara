
rule Backdoor_Linux_FlashBack{
	meta:
		description = "Backdoor:Linux/FlashBack,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {7b 42 53 52 51 7d } //1 {BSRQ}
		$a_01_1 = {2e 67 6f 6f 67 6c 65 2e } //1 .google.
		$a_01_2 = {68 77 2e 6d 61 63 68 69 6e 65 } //1 hw.machine
		$a_01_3 = {6b 65 72 6e 2e 6f 73 72 65 6c 65 61 73 65 } //1 kern.osrelease
		$a_01_4 = {2f 4c 69 62 72 61 72 79 2f 50 72 65 66 65 72 65 6e 63 65 73 2f 50 72 65 66 65 72 65 6e 63 65 73 2e 64 79 6c 69 62 } //3 /Library/Preferences/Preferences.dylib
		$a_01_5 = {c1 ea 02 b8 15 02 4d 21 f7 e2 c1 ea 04 8b 45 0c 89 10 eb 07 } //3
		$a_01_6 = {8b 55 d4 80 3a 7b 0f 84 15 02 00 00 8b 72 f4 8b 42 fc 85 c0 78 0b 89 3c 24 } //3
		$a_01_7 = {49 ff c4 48 8b 43 10 48 2b 43 08 48 c1 f8 03 48 ba ab aa aa aa } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3) >=6
 
}