
rule Trojan_Win32_ClipBanker_XP_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.XP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 5d fc 33 d2 8b c1 f7 75 0c 66 8b 04 56 66 31 04 4f 41 3b cb 72 } //00 00 
	condition:
		any of ($a_*)
 
}