
rule Trojan_Win32_Emotet_DW{
	meta:
		description = "Trojan:Win32/Emotet.DW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 00 76 00 7a 00 49 00 4a 00 72 00 74 00 75 00 21 00 4f 00 40 00 } //1 avzIJrtu!O@
		$a_01_1 = {51 58 23 69 47 43 54 69 54 6d 54 5a 74 4d 35 44 6a 45 35 75 2d 57 57 38 58 } //1 QX#iGCTiTmTZtM5DjE5u-WW8X
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}