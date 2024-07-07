
rule Trojan_Win32_Vundo_HA{
	meta:
		description = "Trojan:Win32/Vundo.HA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {bf 60 c4 ea 91 } //1
		$a_01_1 = {81 ef 7a b3 18 21 } //1
		$a_01_2 = {68 41 a6 ea a1 } //1
		$a_01_3 = {b9 30 07 b4 d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}