
rule Trojan_Win32_XRed_AU_MTB{
	meta:
		description = "Trojan:Win32/XRed.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 81 f7 67 ad ed 92 d9 f2 92 28 12 40 05 9e c8 48 a2 af b6 6f bb 99 7a cf 76 b9 a4 33 6f df ac c9 41 f8 8e c6 ba a6 6b 06 eb fc 8b e9 0d 9c 18 b9 04 15 97 58 2c 5f fd 32 cc 47 38 13 7d } //2
		$a_01_1 = {84 33 c9 36 29 47 9f 4c 57 35 8f 5b 14 50 23 33 5c 38 01 35 63 69 95 02 11 03 70 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}