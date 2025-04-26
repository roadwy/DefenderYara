
rule Trojan_Win32_Zegost_RC_MTB{
	meta:
		description = "Trojan:Win32/Zegost.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 64 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //1 bduninstall.exe
		$a_01_1 = {62 63 74 72 6c 2e 65 78 65 } //1 bctrl.exe
		$a_01_2 = {75 6e 64 6f 61 62 6c 65 64 69 73 6b 2e 64 6c 6c } //1 undoabledisk.dll
		$a_01_3 = {64 72 69 76 65 72 73 5c 75 6e 64 6f 76 6f 6c 2e 73 79 73 } //1 drivers\undovol.sys
		$a_01_4 = {68 3a 5c 24 75 64 6a 6f 75 72 24 2e 24 24 24 } //1 h:\$udjour$.$$$
		$a_01_5 = {62 69 74 6e 65 74 32 30 30 35 5c 69 6e 73 74 61 6c 6c 5c 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 64 65 69 6e 73 74 61 6c 6c 2e 70 64 62 } //1 bitnet2005\install\Win32\Release\deinstall.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}