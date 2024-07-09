
rule Trojan_Win32_Autophyte_E_dha{
	meta:
		description = "Trojan:Win32/Autophyte.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {af c6 44 24 [0-01] 3d c6 ?? ?? ?? 78 c6 ?? ?? ?? 23 c6 ?? ?? ?? 4a c6 ?? ?? ?? 79 c6 ?? ?? ?? 92 c6 ?? ?? ?? 81 c6 ?? ?? ?? 9d c6 } //1
		$a_03_1 = {af c6 84 24 [0-04] 3d c6 [0-06] 78 c6 [0-06] 23 c6 [0-06] 4a c6 [0-06] 79 c6 [0-06] 92 c6 [0-06] 81 c6 [0-06] 9d c6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}