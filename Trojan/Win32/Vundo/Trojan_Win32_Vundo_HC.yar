
rule Trojan_Win32_Vundo_HC{
	meta:
		description = "Trojan:Win32/Vundo.HC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 dc 42 24 83 } //1
		$a_01_1 = {b9 f6 31 52 12 } //1
		$a_01_2 = {bb 11 17 dc 33 } //1
		$a_01_3 = {81 c3 60 8a 82 3e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}