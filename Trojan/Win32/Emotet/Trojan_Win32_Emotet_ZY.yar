
rule Trojan_Win32_Emotet_ZY{
	meta:
		description = "Trojan:Win32/Emotet.ZY,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {0f be 03 89 } //5
		$a_03_2 = {d3 e2 01 55 ?? 29 } //5
		$a_01_3 = {80 3b 00 75 } //5
		$a_01_4 = {0f b7 04 78 8b 34 86 03 f5 3b f3 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=21
 
}