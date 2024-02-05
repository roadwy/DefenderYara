
rule Trojan_Win32_DanaBot_AU_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 0f 57 c0 66 0f 13 05 90 02 15 8b 55 90 01 01 03 55 90 01 01 89 55 90 01 01 8b 45 90 01 01 33 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}