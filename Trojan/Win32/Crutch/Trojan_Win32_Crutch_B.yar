
rule Trojan_Win32_Crutch_B{
	meta:
		description = "Trojan:Win32/Crutch.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_80_0 = {32 64 72 6f 70 62 6f 78 2e 72 61 72 } //2dropbox.rar  1
		$a_80_1 = {70 61 73 73 77 6f 72 64 73 2e 72 61 72 } //passwords.rar  1
		$a_80_2 = {25 74 65 6d 70 25 5c 6d 73 77 69 6e 30 30 30 31 2e 6a 73 } //%temp%\mswin0001.js  1
		$a_80_3 = {63 72 75 74 63 68 33 2e 70 64 62 } //crutch3.pdb  10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*10) >=11
 
}