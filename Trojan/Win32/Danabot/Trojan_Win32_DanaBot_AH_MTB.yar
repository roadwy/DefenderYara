
rule Trojan_Win32_DanaBot_AH_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c1 2b f0 90 02 25 89 5c 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 02 60 31 44 24 90 02 40 03 54 24 90 01 01 89 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}