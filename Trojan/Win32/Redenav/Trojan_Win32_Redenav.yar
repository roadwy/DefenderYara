
rule Trojan_Win32_Redenav{
	meta:
		description = "Trojan:Win32/Redenav,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 61 76 65 72 2e 63 6f 6d 00 } //2
		$a_00_1 = {63 6f 6d 2f 6f 76 6e 5f 63 6c 69 63 6b 2e 61 73 70 } //2 com/ovn_click.asp
		$a_00_2 = {63 6f 6d 2f 65 78 65 2f 64 6e 61 6d 65 2e 68 74 6d 6c } //1 com/exe/dname.html
		$a_02_3 = {68 74 74 70 3a 2f 2f [0-02] 6f 6c 62 61 72 32 62 } //1
		$a_00_4 = {72 65 77 61 72 64 2f 72 65 77 61 72 64 2e 61 73 70 3f 6d 6f 64 65 } //1 reward/reward.asp?mode
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 67 75 69 64 65 74 6f 6f 6c 62 61 72 } //1 Software\guidetoolbar
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}