
rule Trojan_Win32_Vundo_KG{
	meta:
		description = "Trojan:Win32/Vundo.KG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {60 e8 06 00 00 00 00 00 00 00 00 00 58 83 c0 08 61 90 02 60 cc 62 40 c6 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}