
rule Trojan_Win32_Waski_E_MTB{
	meta:
		description = "Trojan:Win32/Waski.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b 45 0c c1 e8 02 2b c1 50 f7 f3 [0-03] 29 16 33 d2 58 f7 f3 03 14 24 52 81 04 24 ?? ?? ?? ?? 5a 31 16 83 c6 04 e2 } //1
		$a_02_1 = {03 75 fc 8b 7d 0c 03 7f 3c 83 c7 14 83 c7 04 8b 7f 18 81 c7 ?? ?? ?? ?? 81 ef 00 20 00 00 03 7d 08 50 8b 45 0c 03 40 3c 83 c0 14 83 c0 04 8b 40 18 05 ?? ?? ?? ?? 2d 00 20 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}