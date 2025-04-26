
rule Trojan_Win32_Emotet_GT{
	meta:
		description = "Trojan:Win32/Emotet.GT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 67 6e 6a 4d 78 33 34 41 6a 73 65 27 68 67 66 22 3d 31 31 64 3d 32 63 } //1 XgnjMx34Ajse'hgf"=11d=2c
		$a_01_1 = {4b 6f 6a 6b 4d 31 58 75 48 79 59 2b 48 79 39 2b 3f 7c 4e 74 45 31 4f 78 42 75 41 2b 3e } //1 KojkM1XuHyY+Hy9+?|NtE1OxBuA+>
		$a_01_2 = {3f 6a 4e 72 53 6f 7d 4a 24 6d 45 72 42 6e 7d } //1 ?jNrSo}J$mErBn}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}