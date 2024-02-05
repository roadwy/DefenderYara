
rule Trojan_Win32_Zbot_BX_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {cc 6d 40 00 4c 00 00 00 50 00 00 00 32 6e 58 a2 82 5d f1 41 98 77 } //05 00 
		$a_01_1 = {33 a1 44 89 ba 49 d6 87 08 87 e5 32 6e 58 a2 82 5d f1 41 98 77 } //00 00 
	condition:
		any of ($a_*)
 
}