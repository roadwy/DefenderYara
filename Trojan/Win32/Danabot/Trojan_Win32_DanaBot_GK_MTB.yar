
rule Trojan_Win32_DanaBot_GK_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 3e 56 90 02 25 83 c4 90 01 01 8b f0 3b f3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}