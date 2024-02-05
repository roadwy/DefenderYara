
rule Trojan_Win32_DanaBot_AV_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 33 45 90 00 } //01 00 
		$a_02_1 = {8b 4d e0 8b 55 90 01 01 89 14 01 90 02 10 8b e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}