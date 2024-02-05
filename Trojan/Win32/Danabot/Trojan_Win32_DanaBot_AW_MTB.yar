
rule Trojan_Win32_DanaBot_AW_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c8 0f 57 c0 81 3d 90 02 20 66 0f 13 05 90 02 10 89 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}