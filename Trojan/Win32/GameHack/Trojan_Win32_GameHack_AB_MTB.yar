
rule Trojan_Win32_GameHack_AB_MTB{
	meta:
		description = "Trojan:Win32/GameHack.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {40 53 74 65 61 6d 2e 65 78 65 } //@Steam.exe  3
		$a_80_1 = {73 74 65 61 6d 77 65 62 68 65 6c 70 65 72 2e 65 78 65 } //steamwebhelper.exe  3
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 56 61 6c 76 65 5c 53 74 65 61 6d } //Software\Valve\Steam  3
		$a_80_3 = {56 41 43 20 42 79 70 61 73 73 } //VAC Bypass  3
		$a_80_4 = {42 79 70 61 73 73 20 6d 61 6c 66 75 6e 63 74 69 6f 6e 20 64 65 74 65 63 74 65 64 21 } //Bypass malfunction detected!  3
		$a_80_5 = {53 74 65 61 6d 20 77 69 6c 6c 20 63 6c 6f 73 65 2e 2e 2e } //Steam will close...  3
		$a_80_6 = {73 74 65 61 6d 75 69 2e 64 6c 6c } //steamui.dll  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}