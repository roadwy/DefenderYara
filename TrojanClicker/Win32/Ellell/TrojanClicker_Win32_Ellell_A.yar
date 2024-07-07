
rule TrojanClicker_Win32_Ellell_A{
	meta:
		description = "TrojanClicker:Win32/Ellell.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6e 6f 32 6f 70 6c 6f 76 65 2e 63 6f 6d 2f 6c 6c 6c 6c 2e 68 74 6d 6c 3f 73 65 61 72 63 68 3d } //2 http://no2oplove.com/llll.html?search=
		$a_00_1 = {80 b1 00 30 40 00 5c 41 8b d9 3b d8 74 02 eb f0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}