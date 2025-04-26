
rule Trojan_Win32_Fareit_SB_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {66 72 75 73 74 75 6d } //frustum  3
		$a_80_1 = {74 78 74 50 61 73 73 77 6f 72 64 } //txtPassword  3
		$a_80_2 = {63 6d 64 43 61 6e 63 65 6c } //cmdCancel  3
		$a_80_3 = {63 68 6b 4c 6f 61 64 54 69 70 73 41 74 53 74 61 72 74 75 70 } //chkLoadTipsAtStartup  3
		$a_80_4 = {7b 48 6f 6d 65 7d 2b 7b 45 6e 64 7d } //{Home}+{End}  3
		$a_80_5 = {33 44 5f 6d 61 7a 65 } //3D_maze  3
		$a_80_6 = {54 49 50 4f 46 44 41 59 2e 54 58 54 } //TIPOFDAY.TXT  3
		$a_80_7 = {54 52 4f 43 42 49 54 53 31 32 30 } //TROCBITS120  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}