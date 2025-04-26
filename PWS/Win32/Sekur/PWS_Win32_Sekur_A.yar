
rule PWS_Win32_Sekur_A{
	meta:
		description = "PWS:Win32/Sekur.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {59 59 89 03 57 57 ff 75 08 68 50 24 b7 07 6a 0b e8 ?? ?? ?? ?? 59 59 ff d0 8b 0b 8b 16 89 04 91 85 c0 75 c2 d1 ef 8b 45 08 75 b6 } //1
		$a_02_1 = {57 8b 7d 0c ff 0e 8b 06 ff 34 87 68 04 27 f5 0e 6a 0b e8 ?? ?? ?? ?? 59 59 ff d0 83 3e 00 75 e4 } //1
		$a_02_2 = {8d 45 e8 50 8d 45 a4 50 33 c0 50 50 ff 75 08 50 50 50 ff 75 10 50 68 a1 64 e1 01 50 e8 ?? ?? ?? ?? 59 59 ff d0 } //10
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*10) >=12
 
}