
rule Trojan_Win32_Vebzenpak_GV_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 1c 0a 50 90 02 20 81 f3 90 02 30 f7 d7 90 02 20 89 1c 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}