
rule Trojan_Win32_Daonol_N{
	meta:
		description = "Trojan:Win32/Daonol.N,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {aa 8b 45 c4 ff 40 f1 } //3
		$a_03_1 = {ff 74 87 d0 81 fe ?? ?? 00 00 } //1
		$a_03_2 = {ff 74 47 02 81 fe ?? ?? 00 00 } //1
		$a_03_3 = {ff 74 87 fc 81 fe ?? ?? 00 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}