
rule Trojan_Win32_DanaBot_BC_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d0 d3 e2 8b c8 c1 e9 90 01 01 03 4d 90 01 01 03 55 90 01 01 89 3d 90 01 04 33 d1 8b 4d 90 01 01 03 c8 33 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}