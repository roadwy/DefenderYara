
rule Trojan_Win32_Vundo_OT{
	meta:
		description = "Trojan:Win32/Vundo.OT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c9 03 d1 8b ca c1 e9 0f c1 e2 11 0b ca 81 c1 ?? ?? ?? 00 8b d1 8a 08 40 40 84 c9 } //1
		$a_03_1 = {2b c7 8b 34 38 8b dd 83 e3 1f 6a 20 59 2b cb 8b d6 d3 e2 8b cb d3 ee 0b d6 81 c2 ?? ?? 00 00 8b ca c1 e1 14 c1 ea 0c 0b ca } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}