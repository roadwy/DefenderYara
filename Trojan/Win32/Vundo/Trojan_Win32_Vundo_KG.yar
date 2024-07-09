
rule Trojan_Win32_Vundo_KG{
	meta:
		description = "Trojan:Win32/Vundo.KG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {60 e8 06 00 00 00 00 00 00 00 00 00 58 83 c0 08 61 [0-60] cc 62 40 c6 d4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}