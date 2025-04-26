
rule Trojan_Win32_Vundo_HB{
	meta:
		description = "Trojan:Win32/Vundo.HB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 09 e4 cb fc } //1
		$a_01_1 = {bb dd 2c 06 74 } //1
		$a_01_2 = {b9 95 97 56 2a } //1
		$a_01_3 = {81 f1 e4 36 08 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}