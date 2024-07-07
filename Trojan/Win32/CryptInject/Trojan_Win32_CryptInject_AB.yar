
rule Trojan_Win32_CryptInject_AB{
	meta:
		description = "Trojan:Win32/CryptInject.AB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 00 6d 00 73 00 75 00 58 00 45 00 56 00 74 00 3d 00 23 00 2b 00 25 00 44 00 72 00 42 00 26 00 70 00 3e 00 2f 00 71 00 } //1 GmsuXEVt=#+%DrB&p>/q
		$a_01_1 = {66 00 72 00 6f 00 6d 00 66 00 75 00 63 00 6b 00 79 00 6f 00 75 00 78 00 61 00 6e 00 64 00 } //1 fromfuckyouxand
		$a_01_2 = {66 61 69 6c 65 64 2e 66 4b 65 6c 65 63 74 65 64 70 4a 75 6c 79 61 6e 64 68 61 73 } //1 failed.fKelectedpJulyandhas
		$a_01_3 = {72 65 6c 65 61 73 65 73 5c 6f 35 36 47 74 72 65 61 64 44 65 73 6b 74 6f 70 76 38 33 30 34 35 70 36 2e 70 64 62 } //1 releases\o56GtreadDesktopv83045p6.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}