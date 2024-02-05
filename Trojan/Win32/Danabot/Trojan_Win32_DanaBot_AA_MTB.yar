
rule Trojan_Win32_DanaBot_AA_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c8 03 7c 24 90 01 01 0f 57 c0 81 3d 90 02 30 c7 05 90 02 30 66 0f 13 05 90 02 30 89 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}