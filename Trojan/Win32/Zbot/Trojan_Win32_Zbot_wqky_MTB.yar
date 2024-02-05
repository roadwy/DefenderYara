
rule Trojan_Win32_Zbot_wqky_MTB{
	meta:
		description = "Trojan:Win32/Zbot.wqky!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 06 33 c1 e8 7b 00 00 00 c3 } //0a 00 
		$a_01_1 = {8b c8 88 07 83 c6 01 c3 } //00 00 
	condition:
		any of ($a_*)
 
}