
rule Trojan_Win32_DanaBot_GM_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 3e b8 01 00 00 00 29 85 90 01 04 8b b5 90 01 04 3b f3 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}